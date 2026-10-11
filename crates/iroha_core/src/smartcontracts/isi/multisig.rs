//! Built-in handling for multisig instructions without requiring an executor upgrade.
#[path = "multisig_fee_proposal.rs"]
mod fee_proposal;
mod parliament_rekey;
pub(crate) use fee_proposal::{
    fee_proposal_key_is_unused, read_pending_fee_proposal, read_registered_account_state,
    read_settled_fee_proposal,
};

#[cfg(test)]
pub(crate) use fee_proposal::install_executed_fee_proposal_fixture;

use crate::{
    execution_attempt::{
        ExecutionAttemptError as Attempt, json_decode_attempt_error, norito_decode_attempt_error,
    },
    smartcontracts::Execute,
    smartcontracts::isi::domain::isi::ensure_controller_capabilities,
    state::{
        StateTransaction, WorldReadOnly, public_lane_stake_share_matches_key,
        public_lane_validator_record_matches_key, retail_daily_limit_state as retail_state,
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    ValidationFail,
    account::{AccountId, MultisigMember, MultisigPolicy},
    isi::{
        AddSignatory, InstructionBox, RemoveSignatory, SetAccountQuorum,
        error::{InstructionExecutionError, InvalidParameterError},
    },
    permission::Permission,
    prelude::{Grant, Json, Level, Log, Register, Revoke},
    query::error::{FindError, QueryExecutionFail},
    role::{Role, RoleId},
};
use iroha_executor_data_model::isi::multisig::{
    DEFAULT_MULTISIG_TTL_MS, MultisigAccountState, MultisigApprovalOutcomeStatusV1,
    MultisigApprovalOutcomeV1, MultisigApprove, MultisigCancel, MultisigInstructionBox,
    MultisigInvalidateOutstanding, MultisigProposalState, MultisigProposalTerminalExecutionStateV1,
    MultisigProposalTerminalState, MultisigProposalTerminalStatus, MultisigProposalValue,
    MultisigPropose, MultisigRegister, MultisigSpec,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::{name::Name, state_path::StatePath};
use mv::storage::StorageReadOnly;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::LazyLock,
};
const DELIMITER: char = '/';
const MULTISIG: &str = "multisig";
const MULTISIG_ACCOUNT_STATE: &str = "account";
const MULTISIG_PROPOSAL_STATE: &str = "proposal";
const MULTISIG_PROPOSAL_TERMINAL_STATE: &str = "proposal-terminal";
const MULTISIG_PROPOSAL_TERMINAL_EXECUTION_STATE: &str = "proposal-terminal-execution";
const MULTISIG_APPROVAL_OUTCOME_STATE: &str = "approval-outcome";
const MULTISIG_SIGNATORY_INDEX_STATE: &str = "signatory";
const MULTISIG_SIGNATORY: &str = "MULTISIG_SIGNATORY";
const DOMAINLESS_NAMESPACE: &str = "domainless";
pub(crate) const MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH: usize = 64;
type MultisigDeferredExecutionId = (AccountId, HashOf<Vec<InstructionBox>>);

/// Retain the original JSON or binary refusal while classifying a custom multisig instruction.
pub(crate) fn multisig_instruction_decode_attempt<E>(
    error: norito::Error,
    rejected: impl FnOnce(norito::Error) -> E,
) -> Attempt<E> {
    match error {
        norito::Error::Json(error) => {
            json_decode_attempt_error(error, |error| rejected(norito::Error::Json(error)))
        }
        error => norito_decode_attempt_error(error, rejected),
    }
}
static MULTISIG_CREATED_VIA_KEY: LazyLock<Name> = LazyLock::new(|| {
    "iroha:created_via"
        .parse()
        .expect("multisig created_via metadata key must be valid")
});
static MULTISIG_HOME_DOMAIN_KEY: LazyLock<Name> = LazyLock::new(|| {
    "iroha:multisig_home_domain"
        .parse()
        .expect("multisig home-domain metadata key must be valid")
});
static MULTISIG_PROPOSAL_METADATA_PREFIX: LazyLock<String> =
    LazyLock::new(|| format!("{MULTISIG}{DELIMITER}proposals{DELIMITER}"));
/// Execute a multisig instruction directly in the initial executor.
///
/// # Errors
///
/// Propagates [`ValidationFail`] when validation or execution of the instruction fails.
pub fn execute_multisig_instruction(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: MultisigInstructionBox,
) -> Result<(), ValidationFail> {
    match instruction {
        MultisigInstructionBox::Register(instruction) => {
            execute_register(state_transaction, authority, instruction)
        }
        MultisigInstructionBox::Propose(instruction) => {
            execute_propose(state_transaction, authority, &instruction)
        }
        MultisigInstructionBox::Approve(instruction) => {
            execute_approve(state_transaction, authority, &instruction)
        }
        MultisigInstructionBox::Cancel(instruction) => {
            execute_cancel(state_transaction, authority, &instruction)
        }
        MultisigInstructionBox::InvalidateOutstanding(instruction) => {
            execute_invalidate_outstanding(state_transaction, authority, &instruction)
        }
    }
}
/// Return the concrete instructions a live multisig approval can execute.
///
/// This read-only projection is used by non-bypassable deferred-execution admission. Missing,
/// expired or terminal proposals resolve to `None`. Malformed state rejects deterministically;
/// an unfinished local read retains its original decoder refusal.
pub(crate) fn live_proposal_instructions_for_approval(
    state_transaction: &StateTransaction<'_, '_>,
    approve: &MultisigApprove,
) -> Result<Option<(AccountId, Vec<InstructionBox>)>, Attempt<ValidationFail>> {
    let proposal = match proposal_state_attempt(
        state_transaction,
        &approve.account,
        &approve.instructions_hash,
    ) {
        Ok(proposal) => proposal,
        Err(Attempt::Rejected(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if now_ms(state_transaction) >= proposal.expires_at_ms || proposal.is_relayed == Some(true) {
        return Ok(None);
    }
    Ok(Some((proposal.multisig_account_id, proposal.instructions)))
}
pub(crate) fn is_reserved_multisig_metadata_key(key: &Name) -> bool {
    let literal = key.as_ref();
    literal == spec_key().as_ref()
        || literal == home_domain_key().as_ref()
        || literal.starts_with(MULTISIG_PROPOSAL_METADATA_PREFIX.as_str())
}
impl Execute for AddSignatory {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let AddSignatory {
            account: input_account,
            signatory,
        } = self;
        let account = resolve_account_for_instruction(state_transaction, &input_account)?;
        let home_domain =
            multisig_home_domain(state_transaction, &account).map_err(map_validation_fail)?;
        let previous_account_state =
            load_multisig_account_state_optional(state_transaction, &account)
                .map_err(map_validation_fail)?;
        let mut spec = multisig_spec_strict(state_transaction, &account)?;
        let signatory_account = AccountId::new(signatory);
        if spec_contains_signatory_subject(&spec, &signatory_account) {
            return Err(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(format!(
                    "signatory `{signatory_account}` already present in multisig spec for `{account}`"
                )),
            ));
        }
        spec.signatories.insert(signatory_account.clone(), 1);
        validate_registration(state_transaction, &account, &spec).map_err(map_validation_fail)?;
        let updated_account =
            rekey_multisig_account(state_transaction, &account, home_domain.as_ref(), &spec)?;
        persist_multisig_account_state(
            state_transaction,
            previous_account_state.as_ref(),
            &MultisigAccountState::new(updated_account.clone(), home_domain.clone(), spec.clone()),
        )
        .map_err(map_validation_fail)?;
        materialize_missing_signatory_accounts(
            state_transaction,
            home_domain.as_ref(),
            &updated_account,
            &spec,
        )
        .map_err(map_validation_fail)?;
        let role_owner = if let Some(home_domain) = home_domain.as_ref() {
            domain_owner(state_transaction, home_domain).map_err(map_validation_fail)?
        } else {
            updated_account.clone()
        };
        configure_roles(
            state_transaction,
            &role_owner,
            home_domain.as_ref(),
            &updated_account,
            &spec,
        )
        .map_err(map_validation_fail)?;
        Ok(())
    }
}
impl Execute for RemoveSignatory {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let RemoveSignatory {
            account: input_account,
            signatory,
        } = self;
        let account = resolve_account_for_instruction(state_transaction, &input_account)?;
        let home_domain =
            multisig_home_domain(state_transaction, &account).map_err(map_validation_fail)?;
        let previous_account_state =
            load_multisig_account_state_optional(state_transaction, &account)
                .map_err(map_validation_fail)?;
        let mut spec = multisig_spec_strict(state_transaction, &account)?;
        let signatory_candidate = AccountId::new(signatory);
        let Some(signatory_account) = spec
            .signatories
            .keys()
            .find(|existing| existing.subject_id() == signatory_candidate.subject_id())
            .cloned()
        else {
            return Err(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(format!(
                    "signatory `{signatory_candidate}` not present in multisig spec for `{account}`"
                )),
            ));
        };
        let _removed = spec.signatories.remove(&signatory_account);
        let total_weight: u32 = spec
            .signatories
            .values()
            .map(|weight| u32::from(*weight))
            .sum();
        let quorum = u32::from(spec.quorum.get());
        if total_weight > 0 && total_weight < quorum {
            // Keep the quorum reachable after removing a signatory.
            let adjusted = u16::try_from(total_weight).map_err(|_| {
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    format!("multisig total weight {total_weight} exceeds u16"),
                ))
            })?;
            spec.quorum = std::num::NonZeroU16::new(adjusted)
                .expect("total_weight > 0 implies nonzero quorum");
        }
        validate_registration(state_transaction, &account, &spec).map_err(map_validation_fail)?;
        let updated_account =
            rekey_multisig_account(state_transaction, &account, home_domain.as_ref(), &spec)?;
        persist_multisig_account_state(
            state_transaction,
            previous_account_state.as_ref(),
            &MultisigAccountState::new(updated_account.clone(), home_domain.clone(), spec.clone()),
        )
        .map_err(map_validation_fail)?;
        let resolved_signatory_account =
            resolve_signatory_account(state_transaction, &signatory_account)
                .map_err(map_validation_fail)?;
        let multisig_role_id = multisig_role_for(home_domain.as_ref(), &updated_account);
        if has_role(
            state_transaction,
            &resolved_signatory_account,
            &multisig_role_id,
        )
        .map_err(map_validation_fail)?
        {
            Revoke::account_role(multisig_role_id.clone(), resolved_signatory_account.clone())
                .execute(authority, state_transaction)?;
        }
        let signatory_role_id =
            multisig_role_for(home_domain.as_ref(), &resolved_signatory_account);
        if has_role(state_transaction, &updated_account, &signatory_role_id)
            .map_err(map_validation_fail)?
        {
            Revoke::account_role(signatory_role_id, updated_account.clone())
                .execute(authority, state_transaction)?;
        }
        Ok(())
    }
}
impl Execute for SetAccountQuorum {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        let SetAccountQuorum {
            account: input_account,
            quorum,
        } = self;
        let account = resolve_account_for_instruction(state_transaction, &input_account)?;
        let home_domain =
            multisig_home_domain(state_transaction, &account).map_err(map_validation_fail)?;
        let previous_account_state =
            load_multisig_account_state_optional(state_transaction, &account)
                .map_err(map_validation_fail)?;
        let mut spec = multisig_spec_strict(state_transaction, &account)?;
        spec.quorum = quorum;
        validate_registration(state_transaction, &account, &spec).map_err(map_validation_fail)?;
        let updated_account =
            rekey_multisig_account(state_transaction, &account, home_domain.as_ref(), &spec)?;
        persist_multisig_account_state(
            state_transaction,
            previous_account_state.as_ref(),
            &MultisigAccountState::new(updated_account, home_domain, spec),
        )
        .map_err(map_validation_fail)?;
        Ok(())
    }
}
pub(crate) fn spec_key() -> Name {
    Name::from_str(&format!("{MULTISIG}{DELIMITER}spec"))
        .expect("constant string must be a valid name")
}
fn home_domain_key() -> Name {
    (*MULTISIG_HOME_DOMAIN_KEY).clone()
}
pub(crate) fn multisig_account_state_key(account: &AccountId) -> StatePath {
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_ACCOUNT_STATE}{DELIMITER}{}",
        HashOf::new(account)
    ))
    .expect("multisig account state path must be valid")
}
fn multisig_signatory_index_key(signatory: &AccountId) -> StatePath {
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_SIGNATORY_INDEX_STATE}{DELIMITER}{}",
        HashOf::new(&signatory.subject_id())
    ))
    .expect("multisig signatory state path must be valid")
}
fn multisig_proposal_state_prefix(account: &AccountId) -> StatePath {
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_PROPOSAL_STATE}{DELIMITER}{}{DELIMITER}",
        HashOf::new(account)
    ))
    .expect("multisig proposal state prefix must be valid")
}
fn multisig_proposal_state_key(
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> StatePath {
    StatePath::from_str(&format!(
        "{}{}",
        multisig_proposal_state_prefix(multisig_account),
        instructions_hash
    ))
    .expect("constant string must be a valid state path")
}
fn multisig_proposal_terminal_state_prefix(account: &AccountId) -> StatePath {
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_PROPOSAL_TERMINAL_STATE}{DELIMITER}{}{DELIMITER}",
        HashOf::new(account)
    ))
    .expect("multisig proposal terminal state prefix must be valid")
}
fn multisig_proposal_terminal_state_key(
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> StatePath {
    StatePath::from_str(&format!(
        "{}{}",
        multisig_proposal_terminal_state_prefix(multisig_account),
        instructions_hash
    ))
    .expect("multisig proposal terminal state path must be valid")
}
/// Canonical immutable native multisig terminal-execution record key.
#[must_use]
pub fn multisig_proposal_terminal_execution_state_key(
    terminal_entrypoint_hash: [u8; Hash::LENGTH],
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> StatePath {
    let terminal_entrypoint_hash = Hash::prehashed(terminal_entrypoint_hash);
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_PROPOSAL_TERMINAL_EXECUTION_STATE}{DELIMITER}{terminal_entrypoint_hash}{DELIMITER}{}{DELIMITER}{instructions_hash}",
        HashOf::new(multisig_account),
    ))
    .expect("multisig proposal terminal execution path must be valid")
}
/// Canonical immutable native multisig approval-outcome record key.
#[must_use]
pub fn multisig_approval_outcome_state_key(
    entrypoint_hash: [u8; Hash::LENGTH],
    entrypoint_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> StatePath {
    let entrypoint_hash = Hash::prehashed(entrypoint_hash);
    StatePath::from_str(&format!(
        "{MULTISIG}{DELIMITER}{MULTISIG_APPROVAL_OUTCOME_STATE}{DELIMITER}{entrypoint_hash}{DELIMITER}{}{DELIMITER}{instructions_hash}",
        HashOf::new(entrypoint_account),
    ))
    .expect("multisig approval outcome path must be valid")
}
fn account_role_suffix(account: &AccountId) -> String {
    const MAX_CANONICAL_SUFFIX_LEN: usize = 128;
    if let Ok(canonical_suffix) = account.canonical_i105() {
        if canonical_suffix.len() <= MAX_CANONICAL_SUFFIX_LEN {
            return canonical_suffix;
        }
    }
    HashOf::new(account).to_string()
}
fn multisig_role_for(
    home_domain: Option<&iroha_model_base::domain::DomainId>,
    account: &AccountId,
) -> RoleId {
    let suffix = account_role_suffix(account);
    let literal = if let Some(home_domain) = home_domain {
        format!(
            "{MULTISIG_SIGNATORY}{DELIMITER}{}{DELIMITER}{}",
            home_domain, suffix,
        )
    } else {
        format!("{MULTISIG_SIGNATORY}{DELIMITER}{DOMAINLESS_NAMESPACE}{DELIMITER}{suffix}")
    };
    literal.parse().expect("multisig role name must be valid")
}
fn rekey_multisig_account(
    state_transaction: &mut StateTransaction<'_, '_>,
    account: &AccountId,
    home_domain: Option<&iroha_model_base::domain::DomainId>,
    spec: &MultisigSpec,
) -> Result<AccountId, InstructionExecutionError> {
    ensure_signatories_are_single(spec).map_err(map_validation_fail)?;
    let policy = multisig_policy_from_spec(spec)?;
    let updated_account = AccountId::new_multisig(policy);
    ensure_controller_capabilities(
        updated_account.controller(),
        &state_transaction.crypto.allowed_signing,
        &state_transaction.crypto.allowed_curve_ids,
    )?;
    if &updated_account == account {
        return Ok(account.clone());
    }
    if account_exists(state_transaction, &updated_account).map_err(map_validation_fail)? {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("multisig account `{updated_account}` already exists").into(),
        ));
    }
    rekey_account_id(state_transaction, account, &updated_account, home_domain)?;
    state_transaction
        .world
        .smart_contract_state
        .remove(multisig_account_state_key(account));
    move_multisig_proposals(state_transaction, account, &updated_account)
        .map_err(map_validation_fail)?;
    Ok(updated_account)
}
fn multisig_policy_from_spec(
    spec: &MultisigSpec,
) -> Result<MultisigPolicy, InstructionExecutionError> {
    let mut members = Vec::with_capacity(spec.signatories.len());
    for (account, weight) in &spec.signatories {
        let Some(signatory) = account.controller().single_signatory() else {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("multisig signatory `{account}` must be a single-key account").into(),
            ));
        };
        let member = MultisigMember::new(signatory.clone(), u16::from(*weight)).map_err(|err| {
            InstructionExecutionError::InvariantViolation(format!("{err}").into())
        })?;
        members.push(member);
    }
    MultisigPolicy::new(spec.quorum.get(), members)
        .map_err(|err| InstructionExecutionError::InvariantViolation(format!("{err}").into()))
}

fn rekey_account_id(
    state_transaction: &mut StateTransaction<'_, '_>,
    old_account: &AccountId,
    new_account: &AccountId,
    home_domain: Option<&iroha_model_base::domain::DomainId>,
) -> Result<(), InstructionExecutionError> {
    // A controller change cannot silently create a new retail identity or
    // discard an existing issuer attestation. A future owner-governed rekey
    // instruction must preserve the exact identity and DAY usage atomically.
    let has_retail_binding =
        retail_state::account_is_retained(state_transaction.world(), old_account)
            .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
    let holds_retail_governed_asset = state_transaction
        .world
        .assets_in_account_iter(old_account)
        .try_fold(false, |found, asset| {
            retail_state::has_policy_for_definition(
                state_transaction.world(),
                asset.id().definition(),
            )
            .map(|governed| found || governed)
        })
        .map_err(|reason| InstructionExecutionError::InvariantViolation(reason.into()))?;
    if has_retail_binding || holds_retail_governed_asset {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("cannot rekey account {old_account}: retail identity continuity requires an owner-governed transition").into(),
        ));
    }
    if let Some(contract) = crate::smartcontracts::code::historical_contract_for_subject(
        &state_transaction.world,
        old_account,
    ) {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "cannot rekey account {old_account}: it is the retained subject of contract `{contract}`"
            )
            .into(),
        ));
    }
    if super::game::retained_game_account(state_transaction.world(), old_account)
        || crate::smartcontracts::isi::nft_custody::retained_nft_account(
            state_transaction.world(),
            old_account,
        )
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("cannot rekey account {old_account}: it is retained by a native game session or NFT custody").into(),
        ));
    }
    if let Some(reference) =
        crate::smartcontracts::isi::sorafs_moderation::retained_moderation_account_reference(
            state_transaction.world(),
            old_account,
        )?
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("cannot rekey account {old_account}: it is retained by moderation {reference}")
                .into(),
        ));
    }
    if let Some(contract) = crate::smartcontracts::code::contract_owned_or_pending_for_account(
        &state_transaction.world,
        old_account,
    ) {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "cannot rekey account {old_account}: transfer or cancel its lifecycle ownership of contract `{contract}` first"
            )
            .into(),
        ));
    }
    if crate::smartcontracts::isi::escrow::is_protocol_escrow_custody_account(
        state_transaction,
        old_account,
    ) {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "cannot rekey account {old_account}: it is retained native escrow or VPN lease custody"
            )
            .into(),
        ));
    }
    if crate::smartcontracts::isi::asset::isi::is_fx_corridor_escrow_account(
        state_transaction,
        old_account,
    )? {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("cannot rekey account {old_account}: it is deterministic FX protocol escrow")
                .into(),
        ));
    }
    if crate::smartcontracts::isi::vpn::is_active_vpn_client(&state_transaction.world, old_account)
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "cannot rekey account {old_account}: it funds an active operator-signed VPN lease"
            )
            .into(),
        ));
    }
    if state_transaction.world.accounts.get(new_account).is_some() {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("account `{new_account}` already exists").into(),
        ));
    }
    crate::smartcontracts::isi::kaigi::ensure_account_id_is_not_retired_rekey_predecessor(
        state_transaction,
        new_account,
    )?;
    let account_value = state_transaction
        .world
        .accounts
        .get(old_account)
        .cloned()
        .ok_or_else(|| InstructionExecutionError::Find(FindError::Account(old_account.clone())))?;
    // Parliament candidate roots, seat assignments, proposal fingerprints, and live,
    // operational, or retryable operator-bound proposal references are immutable. Rewriting
    // those records would invalidate their hashes, while moving only the account/citizenship
    // record would strand member actions or release the retained bond under the replacement
    // identity. Reject before any rekey write.
    parliament_rekey::ensure_account_rekey_preserves_bindings(state_transaction, old_account)?;
    // Rewriting historical participants would invalidate the complete intent hash.
    // Pin every receipt variant before any account, permission or index mutation.
    ensure_settlement_receipts_allow_rekey(state_transaction, old_account)?;
    let privacy_reserve_custody = crate::privacy_state::load_privacy_public_reserve_custody_v1(
        &state_transaction.world.privacy_commitments,
    )
    .map_err(|message| {
        InstructionExecutionError::InvariantViolation(
            format!(
                "cannot rekey account {old_account}: privacy reserve custody is invalid: {message}"
            )
            .into(),
        )
    })?;
    if let Some((_, owner)) = privacy_reserve_custody
        .iter()
        .find(|(asset_id, _)| asset_id.account() == old_account)
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "cannot rekey account {old_account}: it is the reserve account for governed privacy pool {:?}",
                owner.namespace()
            )
            .into(),
        ));
    }
    let mut labels_to_repoint: BTreeSet<_> = state_transaction
        .world
        .account_aliases_by_account
        .get(old_account)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    labels_to_repoint.extend(
        state_transaction
            .world
            .account_rekey_records_by_account
            .get(old_account)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .filter(|label| {
                state_transaction
                    .world
                    .account_rekey_records
                    .get(label)
                    .is_some_and(|record| &record.active_account_id == old_account)
            })
            .cloned(),
    );
    if let Some(label) = account_value.label().cloned() {
        labels_to_repoint.insert(label);
    }
    if labels_to_repoint.is_empty() {
        crate::smartcontracts::isi::kaigi::ensure_kaigi_account_can_rekey_without_continuity(
            state_transaction,
            old_account,
        )?;
    }
    // Alias bindings and authoritative SNS ownership are one invariant. Scan the authoritative
    // namespace, rather than only the binding indexes, so acquired-but-unbound and
    // binding-cleared leases are migrated too. Preflight every update before mutating state.
    let alias_lease_updates = crate::sns::prepare_all_account_alias_lease_rekeys(
        state_transaction,
        old_account,
        new_account,
    )
    .map_err(|err| {
        if err.deferral().is_some() {
            return err.retain_in_instruction(state_transaction);
        }
        InstructionExecutionError::InvariantViolation(
            format!("cannot preflight account-alias leases for rekey: {err}").into(),
        )
    })?;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    for label in &labels_to_repoint {
        let Some((_, record)) = alias_lease_updates.get(label) else {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("cannot rekey account alias `{label:?}`: authoritative SNS lease is missing or owned by another account").into(),
            ));
        };
        if !matches!(
            crate::sns::effective_status(record, now_ms),
            iroha_data_model::sns::NameStatus::Active
        ) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot rekey account alias `{label:?}`: authoritative SNS lease is not active"
                )
                .into(),
            ));
        }
    }
    // Build every continuity update before changing the account table. A malformed or missing
    // record must fail this canonical rekey atomically instead of leaving a partially moved
    // account when this helper is exercised directly.
    let mut rekey_record_updates = Vec::with_capacity(labels_to_repoint.len());
    for label in &labels_to_repoint {
        let record = state_transaction
            .world
            .account_rekey_records
            .get(label)
            .cloned()
            .ok_or_else(|| {
                InstructionExecutionError::InvariantViolation(
                    format!(
                        "cannot rekey account alias `{label:?}` without its canonical continuity record"
                    )
                    .into(),
                )
            })?;
        if &record.label != label || &record.active_account_id != old_account {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "cannot rekey account alias `{label:?}` whose continuity record does not target `{old_account}`"
                )
                .into(),
            ));
        }
        let record = record
            .repoint_for_account_id_rekey(new_account.clone())
            .map_err(|error| {
                InstructionExecutionError::InvariantViolation(
                    format!("cannot extend malformed account rekey history: {error}").into(),
                )
            })?;
        rekey_record_updates.push((label.clone(), record));
    }
    let old_multisig_role = multisig_role_for(home_domain, old_account);
    let new_multisig_role = multisig_role_for(home_domain, new_account);
    if old_multisig_role != new_multisig_role
        && state_transaction
            .world
            .roles
            .get(&new_multisig_role)
            .is_some()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("role `{new_multisig_role}` already exists").into(),
        ));
    }
    let assets_to_move: Vec<_> = state_transaction
        .world
        .assets_in_account_iter(old_account)
        .map(|asset| asset.id().clone())
        .collect();
    for asset_id in &assets_to_move {
        let new_asset_id = iroha_data_model::asset::AssetId::with_scope(
            asset_id.definition().clone(),
            new_account.clone(),
            *asset_id.scope(),
        );
        if state_transaction.world.assets.get(&new_asset_id).is_some() {
            return Err(InstructionExecutionError::InvariantViolation(
                format!("asset `{new_asset_id}` already exists").into(),
            ));
        }
    }
    let old_global_trigger_permission: Permission =
        iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
            authority: old_account.clone(),
        }
        .into();
    let global_trigger_permission_grantees = state_transaction
        .world
        .triggers
        .global_data_trigger_permission_rekeys(old_account, new_account)
        .map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("cannot preflight data-trigger account rekey: {error}").into(),
            )
        })?
        .into_iter()
        .filter_map(|(current_grantee, migrated_grantee)| {
            state_transaction
                .world
                .account_permissions
                .get(&current_grantee)
                .is_some_and(|permissions| permissions.contains(&old_global_trigger_permission))
                .then_some(migrated_grantee)
        })
        .collect::<BTreeSet<_>>();
    crate::retail_fee::prepare_rekey(state_transaction, old_account, new_account)?;
    crate::validation_fee_rewards::rekey_beneficiary(state_transaction, old_account, new_account)?;
    state_transaction
        .validate_fastpq_governance_rekey(old_account, new_account)
        .map_err(|error| state_transaction.mandatory_source_instruction_error(error))?;
    state_transaction
        .world
        .triggers
        .replace_account_id(old_account, new_account)
        .map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("cannot apply preflighted data-trigger account rekey: {error}").into(),
            )
        })?;
    // A controller change ends the lifecycle of the old controller-derived AccountId. Remove
    // permissions whose payload targets that identifier before it becomes absent; otherwise an
    // aliasless rekey followed by re-registration of the old ID would reactivate stale direct or
    // role-derived authority against the new account lifecycle.
    crate::smartcontracts::isi::domain::isi::remove_account_associated_permissions(
        state_transaction,
        old_account,
    );
    state_transaction
        .world
        .accounts
        .remove(old_account.clone())
        .expect("account existence was preflighted");
    state_transaction
        .world
        .accounts
        .insert(new_account.clone(), account_value.clone());
    for (label, record) in rekey_record_updates {
        state_transaction
            .world
            .insert_account_alias_binding(label.clone(), new_account.clone());
        debug_assert_eq!(label, record.label);
        state_transaction.world.replace_account_rekey_record(record);
    }
    for (_, (storage_key, record)) in alias_lease_updates {
        state_transaction
            .world
            .smart_contract_state
            .insert(storage_key, norito::codec::Encode::encode(&record));
    }
    if let Some(uaid) = account_value.uaid().copied() {
        state_transaction
            .world
            .uaid_accounts
            .insert(uaid, new_account.clone());
        state_transaction.rebuild_space_directory_bindings(uaid);
    }
    if let Some(sequence) = state_transaction
        .world
        .tx_sequences
        .remove(old_account.clone())
    {
        state_transaction
            .world
            .tx_sequences
            .insert(new_account.clone(), sequence);
    }
    if let Some(perms) = state_transaction
        .world
        .account_permissions
        .remove(old_account.clone())
    {
        state_transaction
            .world
            .account_permissions
            .insert(new_account.clone(), perms);
    }
    if old_multisig_role != new_multisig_role {
        if let Some(mut role) = state_transaction
            .world
            .roles
            .remove(old_multisig_role.clone())
        {
            role.id = new_multisig_role.clone();
            state_transaction
                .world
                .roles
                .insert(new_multisig_role.clone(), role);
        }
    }
    let mut role_updates = Vec::new();
    for (role_id, _) in state_transaction.world.account_roles.iter() {
        let mut updated = role_id.clone();
        if updated.account == *old_account {
            updated.account = new_account.clone();
        }
        if updated.id == old_multisig_role {
            updated.id = new_multisig_role.clone();
        }
        if &updated != role_id {
            role_updates.push((role_id.clone(), updated));
        }
    }
    for (old_key, new_key) in role_updates {
        state_transaction.world.account_roles.remove(old_key);
        state_transaction.world.account_roles.insert(new_key, ());
    }
    for asset_id in assets_to_move {
        // Rekey has its own verified authority, but its quantity-source owner is
        // not part of the complete effect relation yet. Preserve the mutation
        // and poison only the rollback-local candidate instead of omitting it.
        state_transaction
            .world
            .quantity_mutation_observation
            .changed();
        let new_asset_id = iroha_data_model::asset::AssetId::with_scope(
            asset_id.definition().clone(),
            new_account.clone(),
            *asset_id.scope(),
        );
        if let Some(value) = state_transaction.world.assets.remove(asset_id.clone()) {
            let is_nonzero = !value.as_ref().is_zero();
            state_transaction
                .world
                .refresh_nonzero_asset_holder(&asset_id);
            state_transaction
                .world
                .untrack_asset_holder_if_empty(&asset_id);
            state_transaction
                .world
                .assets
                .insert(new_asset_id.clone(), value);
            state_transaction.world.track_asset_holder(&new_asset_id);
            if is_nonzero {
                state_transaction
                    .world
                    .track_nonzero_asset_holder(&new_asset_id);
            }
        }
        if let Some(meta) = state_transaction
            .world
            .asset_metadata
            .remove(asset_id.clone())
        {
            state_transaction
                .world
                .asset_metadata
                .insert(new_asset_id, meta);
        }
    }
    crate::retail_fee::finish_rekey(state_transaction, old_account, new_account)?;
    let nft_ids: Vec<_> = state_transaction
        .world
        .nfts_in_account_iter(old_account)
        .map(|nft| nft.id().clone())
        .collect();
    for nft_id in nft_ids {
        if let Some(value) = state_transaction.world.nfts.get_mut(&nft_id) {
            value.owned_by = new_account.clone();
        }
        state_transaction
            .world
            .replace_nft_owner_index(&nft_id, old_account, new_account);
    }
    let domain_ids: Vec<_> = state_transaction
        .world
        .domains_owned_by_iter(old_account)
        .map(|domain| domain.id.clone())
        .collect();
    for domain_id in domain_ids {
        if let Some(domain) = state_transaction.world.domains.get_mut(&domain_id) {
            domain.owned_by = new_account.clone();
        }
        state_transaction
            .world
            .replace_domain_owner_index(&domain_id, old_account, new_account);
    }
    let asset_def_ids: Vec<_> = state_transaction
        .world
        .asset_definitions_owned_by_iter(old_account)
        .map(|definition| definition.id.clone())
        .collect();
    for asset_def_id in asset_def_ids {
        if let Ok(mut definition) = state_transaction
            .world
            .asset_definition_metadata_mut(&asset_def_id)
        {
            definition.set_owned_by(new_account.clone());
        }
        state_transaction
            .world
            .replace_asset_definition_owner_index(&asset_def_id, old_account, new_account);
    }
    let provider_ids: Vec<_> = state_transaction
        .world
        .provider_owners
        .iter()
        .filter(|(_, owner)| *owner == old_account)
        .map(|(id, _)| id.clone())
        .collect();
    for provider_id in provider_ids {
        state_transaction
            .world
            .provider_owners
            .insert(provider_id, new_account.clone());
    }
    replace_account_id_in_public_lane(state_transaction, old_account, new_account);
    replace_account_id_in_repo_agreements(state_transaction, old_account, new_account);
    replace_account_id_in_citizens(state_transaction, old_account, new_account);
    replace_account_id_in_governance(state_transaction, old_account, new_account);
    replace_account_id_in_oracle(state_transaction, old_account, new_account);
    replace_account_id_in_content_bundles(state_transaction, old_account, new_account);
    if !global_trigger_permission_grantees.is_empty() {
        let migrated_permission: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: new_account.clone(),
            }
            .into();
        for grantee in global_trigger_permission_grantees {
            if let Some(permissions) = state_transaction
                .world
                .account_permissions
                .get_mut(&grantee)
            {
                permissions.insert(migrated_permission.clone());
            } else {
                state_transaction.world.account_permissions.insert(
                    grantee.clone(),
                    BTreeSet::from([migrated_permission.clone()]),
                );
            }
            state_transaction.invalidate_permission_cache_for_account(&grantee);
        }
    }
    state_transaction.invalidate_permission_cache_for_account(old_account);
    state_transaction.invalidate_permission_cache_for_account(new_account);
    Ok(())
}
pub(crate) fn replace_account_controller(
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
    old_account: &AccountId,
    new_controller: iroha_data_model::account::AccountController,
) -> Result<AccountId, InstructionExecutionError> {
    // Explicit controller replacement cannot carry approvals granted to the
    // old policy into the new policy. Its owner must first invalidate them in
    // this same atomic instruction batch (as regulated recovery also does).
    let prefix = multisig_proposal_state_prefix(old_account);
    for (key, value) in state_transaction
        .world
        .smart_contract_state
        .range(prefix.clone()..)
    {
        if !key.as_ref().starts_with(prefix.as_ref()) {
            break;
        }
        let proposal = decode_proposal_state_at_key(key, value)
            .map_err(|error| retain_multisig_read_attempt(state_transaction, error))
            .map_err(map_validation_fail)?;
        if proposal.is_relayed != Some(true) {
            return Err(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(
                    "controller replacement requires outstanding multisig proposal invalidation"
                        .into(),
                ),
            ));
        }
    }
    let new_account = match new_controller {
        iroha_data_model::account::AccountController::Single(signatory) => {
            AccountId::new(signatory)
        }
        iroha_data_model::account::AccountController::Multisig(policy) => {
            AccountId::new_multisig(policy)
        }
    };
    ensure_controller_capabilities(
        new_account.controller(),
        &state_transaction.crypto.allowed_signing,
        &state_transaction.crypto.allowed_curve_ids,
    )?;
    if &new_account == old_account {
        return Err(InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(format!(
                "replacement controller for `{old_account}` must change the canonical account id"
            )),
        ));
    }
    if account_exists(state_transaction, &new_account).map_err(map_validation_fail)? {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("account `{new_account}` already exists").into(),
        ));
    }
    let previous_state = load_multisig_account_state_optional(state_transaction, old_account)
        .map_err(map_validation_fail)?;
    if old_account.multisig_policy().is_some() && previous_state.is_none() {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "multisig account `{old_account}` is missing its canonical native account state"
            )
            .into(),
        ));
    }
    let home_domain = previous_state
        .as_ref()
        .and_then(|state| state.home_domain.clone());
    rekey_account_id(
        state_transaction,
        old_account,
        &new_account,
        home_domain.as_ref(),
    )?;
    if previous_state.is_some() {
        state_transaction
            .world
            .smart_contract_state
            .remove(multisig_account_state_key(old_account));
        move_multisig_proposals(state_transaction, old_account, &new_account)
            .map_err(map_validation_fail)?;
    }
    let next_state = if let Some(policy) = new_account.multisig_policy() {
        Some(
            multisig_state_from_policy(
                state_transaction,
                &new_account,
                home_domain.clone(),
                policy,
            )
            .map_err(map_validation_fail)?,
        )
    } else {
        None
    };
    reconcile_multisig_transition(
        authority,
        state_transaction,
        &new_account,
        previous_state.as_ref(),
        next_state.as_ref(),
    )
    .map_err(map_validation_fail)?;
    Ok(new_account)
}
fn replace_account_id(target: &mut AccountId, old: &AccountId, new: &AccountId) -> bool {
    if target == old {
        *target = new.clone();
        true
    } else {
        false
    }
}
fn replace_account_id_in_asset_id(
    asset_id: &iroha_data_model::asset::AssetId,
    old: &AccountId,
    new: &AccountId,
) -> iroha_data_model::asset::AssetId {
    if asset_id.account() == old {
        iroha_data_model::asset::AssetId::with_scope(
            asset_id.definition().clone(),
            new.clone(),
            *asset_id.scope(),
        )
    } else {
        asset_id.clone()
    }
}
fn replace_account_id_in_vec(accounts: &mut Vec<AccountId>, old: &AccountId, new: &AccountId) {
    for account in accounts.iter_mut() {
        replace_account_id(account, old, new);
    }
}
fn replace_account_id_in_set(accounts: &mut BTreeSet<AccountId>, old: &AccountId, new: &AccountId) {
    if accounts.remove(old) {
        accounts.insert(new.clone());
    }
}
fn reconcile_multisig_transition(
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
    active_account: &AccountId,
    previous_state: Option<&MultisigAccountState>,
    next_state: Option<&MultisigAccountState>,
) -> Result<(), ValidationFail> {
    let home_domain = previous_state
        .and_then(|state| state.home_domain.clone())
        .or_else(|| next_state.and_then(|state| state.home_domain.clone()));
    let previous_members = previous_state
        .map(|state| resolved_signatory_accounts(state_transaction, &state.spec))
        .transpose()?
        .unwrap_or_default();
    let next_members = next_state
        .map(|state| resolved_signatory_accounts(state_transaction, &state.spec))
        .transpose()?
        .unwrap_or_default();
    if previous_state.is_some() {
        let multisig_role_id = multisig_role_for(home_domain.as_ref(), active_account);
        for removed in previous_members
            .iter()
            .filter(|candidate| !next_members.contains(candidate))
        {
            revoke_role_if_present(state_transaction, &multisig_role_id, removed, authority)?;
            let signatory_role_id = multisig_role_for(home_domain.as_ref(), removed);
            revoke_role_if_present(
                state_transaction,
                &signatory_role_id,
                active_account,
                authority,
            )?;
        }
        if next_state.is_none() {
            revoke_role_if_present(
                state_transaction,
                &multisig_role_id,
                active_account,
                authority,
            )?;
            sync_multisig_signatory_index(state_transaction, previous_state, None)?;
            clear_multisig_account_metadata(state_transaction, active_account)
                .map_err(map_find_error)?;
        }
    }
    if let Some(next_state) = next_state {
        persist_multisig_account_state(state_transaction, previous_state, next_state)?;
        let role_owner = if let Some(home_domain) = next_state.home_domain.as_ref() {
            domain_owner(state_transaction, home_domain)?
        } else {
            next_state.account_id.clone()
        };
        configure_roles(
            state_transaction,
            &role_owner,
            next_state.home_domain.as_ref(),
            &next_state.account_id,
            &next_state.spec,
        )?;
    }
    Ok(())
}
fn clear_multisig_account_metadata(
    state_transaction: &mut StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), FindError> {
    let account = state_transaction.world.account_mut(account)?;
    let _ = account.remove(&spec_key());
    let _ = account.remove(&home_domain_key());
    Ok(())
}
fn revoke_role_if_present(
    state_transaction: &mut StateTransaction<'_, '_>,
    role_id: &RoleId,
    account: &AccountId,
    authority: &AccountId,
) -> Result<(), ValidationFail> {
    if has_role(state_transaction, account, role_id)? {
        Revoke::account_role(role_id.clone(), account.clone())
            .execute(authority, state_transaction)
            .map_err(ValidationFail::InstructionFailed)?;
    }
    Ok(())
}
fn multisig_state_from_policy(
    state_transaction: &mut StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    home_domain: Option<iroha_model_base::domain::DomainId>,
    policy: &MultisigPolicy,
) -> Result<MultisigAccountState, ValidationFail> {
    let spec = multisig_spec_from_policy(multisig_account, policy)?;
    materialize_missing_signatory_accounts(
        state_transaction,
        home_domain.as_ref(),
        multisig_account,
        &spec,
    )?;
    Ok(MultisigAccountState::new(
        multisig_account.clone(),
        home_domain,
        spec,
    ))
}
fn multisig_spec_from_policy(
    multisig_account: &AccountId,
    policy: &MultisigPolicy,
) -> Result<MultisigSpec, ValidationFail> {
    let mut signatories = BTreeMap::new();
    for member in policy.members() {
        let signatory_account = AccountId::new(member.public_key().clone());
        let weight = u8::try_from(member.weight()).map_err(|_| {
            ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
                "multisig member weight {} exceeds u8 for `{multisig_account}`",
                member.weight()
            )))
        })?;
        signatories.insert(signatory_account, weight);
    }
    let quorum = std::num::NonZeroU16::new(policy.threshold()).ok_or_else(|| {
        ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
            "multisig threshold is zero for `{multisig_account}`"
        )))
    })?;
    let transaction_ttl_ms = std::num::NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS)
        .expect("default multisig ttl must be non-zero");
    Ok(MultisigSpec {
        signatories,
        quorum,
        transaction_ttl_ms,
    })
}
fn replace_account_id_in_public_lane(
    state_transaction: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) {
    let mut validator_updates = Vec::new();
    for (key, record) in state_transaction.world.public_lane_validators.iter() {
        if public_lane_validator_record_matches_key(key, record) && key.1 == *old {
            validator_updates.push((key.clone(), (key.0, new.clone())));
        }
    }
    for (old_key, new_key) in validator_updates {
        if let Some(mut record) = state_transaction
            .world
            .public_lane_validators
            .remove(old_key)
        {
            replace_account_id(&mut record.validator, old, new);
            replace_account_id(&mut record.stake_account, old, new);
            state_transaction
                .world
                .public_lane_validators
                .insert(new_key, record);
        }
    }
    let validator_keys: Vec<_> = state_transaction
        .world
        .public_lane_validators
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    for key in validator_keys {
        if let Some(record) = state_transaction.world.public_lane_validators.get_mut(&key)
            && public_lane_validator_record_matches_key(&key, record)
        {
            replace_account_id(&mut record.validator, old, new);
            replace_account_id(&mut record.stake_account, old, new);
        }
    }
    let mut stake_updates = Vec::new();
    for (key, record) in state_transaction.world.public_lane_stake_shares.iter() {
        if !public_lane_stake_share_matches_key(key, record) {
            continue;
        }
        if key.1 == *old || key.2 == *old {
            let new_validator = if key.1 == *old {
                new.clone()
            } else {
                key.1.clone()
            };
            let new_staker = if key.2 == *old {
                new.clone()
            } else {
                key.2.clone()
            };
            stake_updates.push((key.clone(), (key.0, new_validator, new_staker)));
        }
    }
    for (old_key, new_key) in stake_updates {
        if let Some(mut record) = state_transaction
            .world
            .public_lane_stake_shares
            .remove(old_key)
        {
            replace_account_id(&mut record.validator, old, new);
            replace_account_id(&mut record.staker, old, new);
            state_transaction
                .world
                .public_lane_stake_shares
                .insert(new_key, record);
        }
    }
    let custody_updates = state_transaction
        .world
        .public_lane_stake_custody
        .iter()
        .filter(|((_, validator), (asset, _))| validator == old || asset.account() == old)
        .map(|(key, (asset, amount))| {
            let new_key = (
                key.0,
                if &key.1 == old {
                    new.clone()
                } else {
                    key.1.clone()
                },
            );
            (
                key.clone(),
                new_key,
                replace_account_id_in_asset_id(asset, old, new),
                amount.clone(),
            )
        })
        .collect::<Vec<_>>();
    for (old_key, new_key, asset, amount) in custody_updates {
        state_transaction
            .world
            .public_lane_stake_custody
            .remove(old_key);
        state_transaction
            .world
            .public_lane_stake_custody
            .insert(new_key, (asset, amount));
    }
    let stake_reserve_updates = state_transaction
        .world
        .public_lane_stake_reserves
        .iter()
        .filter(|(asset, _)| asset.account() == old)
        .map(|(asset, amount)| {
            (
                asset.clone(),
                replace_account_id_in_asset_id(asset, old, new),
                amount.clone(),
            )
        })
        .collect::<Vec<_>>();
    for (old_asset, new_asset, amount) in stake_reserve_updates {
        state_transaction
            .world
            .public_lane_stake_reserves
            .remove(old_asset);
        state_transaction
            .world
            .public_lane_stake_reserves
            .insert(new_asset, amount);
    }
}
fn replace_account_id_in_repo_agreements(
    state_transaction: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) {
    let agreement_ids: Vec<_> = state_transaction
        .world
        .repo_agreements
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for agreement_id in agreement_ids {
        if let Some(agreement) = state_transaction
            .world
            .repo_agreements
            .get_mut(&agreement_id)
        {
            replace_account_id(&mut agreement.initiator, old, new);
            replace_account_id(&mut agreement.counterparty, old, new);
            if let Some(custodian) = agreement.custodian.as_mut() {
                replace_account_id(custodian, old, new);
            }
        }
    }
}
fn ensure_settlement_receipts_allow_rekey(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<(), InstructionExecutionError> {
    if let Some((settlement_id, _)) =
        state_transaction
            .world
            .settlement_receipts
            .iter()
            .find(|(_, receipt)| {
                &receipt.authority == account
                    || receipt.details.movements().any(|movement| {
                        movement.source.account() == account
                            || movement.destination.account() == account
                    })
            })
    {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("cannot rekey account {account}: it is referenced by immutable committed settlement receipt {settlement_id}").into(),
        ));
    }
    Ok(())
}
fn replace_account_id_in_citizens(
    state_transaction: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) {
    if let Some(mut record) = state_transaction.world.citizens.remove(old.clone()) {
        replace_account_id(&mut record.owner, old, new);
        state_transaction.world.citizens.insert(new.clone(), record);
    }
    let citizen_ids: Vec<_> = state_transaction
        .world
        .citizens
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for citizen_id in citizen_ids {
        if let Some(record) = state_transaction.world.citizens.get_mut(&citizen_id) {
            replace_account_id(&mut record.owner, old, new);
        }
    }
}
fn replace_account_id_in_governance(
    state_transaction: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) {
    let proposal_ids: Vec<_> = state_transaction
        .world
        .governance_proposals
        .iter()
        .map(|(id, _)| *id)
        .collect();
    for proposal_id in proposal_ids {
        if let Some(record) = state_transaction
            .world
            .governance_proposals
            .get_mut(&proposal_id)
        {
            // An operator-bound proposal's retained proposer is also its embedded operator and
            // is covered by the proposal fingerprint. Live/operational/retryable records were
            // rejected during rekey preflight; exhausted terminal records remain immutable
            // historical evidence and must survive restore-time operator checks byte-for-byte.
            if !parliament_rekey::is_operator_bound_proposal(&record.kind) {
                replace_account_id(&mut record.proposer, old, new);
            }
        }
    }
    let lock_ids: Vec<_> = state_transaction
        .world
        .governance_locks
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for lock_id in lock_ids {
        let Some(mut locks) = state_transaction
            .world
            .governance_locks
            .get(&lock_id)
            .cloned()
        else {
            continue;
        };
        let mut updated = BTreeMap::new();
        for (account, mut record) in std::mem::take(&mut locks.locks) {
            let key = if account == *old {
                new.clone()
            } else {
                account
            };
            replace_account_id(&mut record.owner, old, new);
            updated.insert(key, record);
        }
        locks.locks = updated;
        state_transaction.world.put_governance_locks(lock_id, locks);
    }
    let slash_ids: Vec<_> = state_transaction
        .world
        .governance_slashes
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for slash_id in slash_ids {
        if let Some(slashes) = state_transaction
            .world
            .governance_slashes
            .get_mut(&slash_id)
        {
            let mut updated = BTreeMap::new();
            for (account, record) in std::mem::take(&mut slashes.slashes) {
                let key = if account == *old {
                    new.clone()
                } else {
                    account
                };
                updated.insert(key, record);
            }
            slashes.slashes = updated;
        }
    }
}
fn replace_account_id_in_oracle(
    state_transaction: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) {
    let feed_ids: Vec<_> = state_transaction
        .world
        .oracle_feeds
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for feed_id in feed_ids {
        if let Some(feed) = state_transaction.world.oracle_feeds.get_mut(&feed_id) {
            replace_account_id_in_vec(&mut feed.providers, old, new);
        }
    }
    let change_ids: Vec<_> = state_transaction
        .world
        .oracle_changes
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for change_id in change_ids {
        if let Some(change) = state_transaction.world.oracle_changes.get_mut(&change_id) {
            replace_account_id(&mut change.proposer, old, new);
            replace_account_id_in_vec(&mut change.feed.providers, old, new);
            for stage in &mut change.stages {
                replace_account_id_in_set(&mut stage.approvals, old, new);
                replace_account_id_in_set(&mut stage.rejections, old, new);
            }
        }
    }
    let dispute_ids: Vec<_> = state_transaction
        .world
        .oracle_disputes
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for dispute_id in dispute_ids {
        if let Some(dispute) = state_transaction.world.oracle_disputes.get_mut(&dispute_id) {
            replace_account_id(&mut dispute.challenger, old, new);
            replace_account_id(&mut dispute.target, old, new);
        }
    }
    let mut provider_updates = Vec::new();
    for (key, value) in state_transaction.world.oracle_provider_stats.iter() {
        if key.provider_id == *old {
            let new_key =
                iroha_data_model::oracle::OracleProviderKey::new(key.feed_id.clone(), new.clone());
            provider_updates.push((key.clone(), new_key, *value));
        }
    }
    for (old_key, new_key, value) in provider_updates {
        state_transaction
            .world
            .oracle_provider_stats
            .remove(old_key);
        state_transaction
            .world
            .oracle_provider_stats
            .insert(new_key, value);
    }
    let observation_keys: Vec<_> = state_transaction
        .world
        .oracle_observations
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for observation_key in observation_keys {
        if let Some(window) = state_transaction
            .world
            .oracle_observations
            .get_mut(&observation_key)
        {
            if window.observations.contains_key(old) {
                let mut updated = BTreeMap::new();
                for (provider, observation) in std::mem::take(&mut window.observations) {
                    let provider = if provider == *old {
                        new.clone()
                    } else {
                        provider
                    };
                    updated.insert(provider, observation);
                }
                window.observations = updated;
            }
        }
    }
}
fn replace_account_id_in_content_bundles(
    state_transaction: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) {
    let bundle_ids: Vec<_> = state_transaction
        .world
        .content_bundles
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    for bundle_id in bundle_ids {
        if let Some(bundle) = state_transaction.world.content_bundles.get_mut(&bundle_id) {
            replace_account_id(&mut bundle.created_by, old, new);
        }
    }
}
fn execute_register(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: MultisigRegister,
) -> Result<(), ValidationFail> {
    let MultisigRegister {
        account: multisig_account_id,
        home_domain,
        spec,
        uaid,
    } = instruction;
    validate_registration(state_transaction, &multisig_account_id, &spec)?;
    if account_exists(state_transaction, &multisig_account_id)? {
        let expected_account = AccountId::new_multisig(
            multisig_policy_from_spec(&spec).map_err(ValidationFail::InstructionFailed)?,
        );
        if expected_account != multisig_account_id {
            return Err(ValidationFail::NotPermitted(format!(
                "multisig account `{multisig_account_id}` already exists and cannot be rekeyed to `{expected_account}` by registration"
            )));
        }
        let existing_uaid = state_transaction
            .world
            .account(&multisig_account_id)
            .map_err(|error| ValidationFail::InstructionFailed(error.into()))?
            .uaid()
            .copied();
        if existing_uaid != uaid {
            return Err(ValidationFail::NotPermitted(format!(
                "multisig account `{multisig_account_id}` already exists with a different immutable universal identity"
            )));
        }
        let previous_state = load_multisig_account_state_optional(
            state_transaction,
            &multisig_account_id,
        )?
        .ok_or_else(|| {
            ValidationFail::NotPermitted(format!(
                "multisig account `{multisig_account_id}` already exists without canonical native account state"
            ))
        })?;
        if previous_state.home_domain != home_domain {
            return Err(ValidationFail::NotPermitted(format!(
                "multisig account `{multisig_account_id}` already exists with a different home domain"
            )));
        }
        if previous_state.spec.signatories != spec.signatories
            || previous_state.spec.quorum != spec.quorum
        {
            return Err(ValidationFail::NotPermitted(format!(
                "multisig account `{multisig_account_id}` already exists with a different signatory policy"
            )));
        }
        let next_state = MultisigAccountState::new(multisig_account_id.clone(), home_domain, spec);
        reconcile_multisig_transition(
            authority,
            state_transaction,
            &multisig_account_id,
            Some(&previous_state),
            Some(&next_state),
        )?;
        return Ok(());
    }
    let register_account =
        iroha_data_model::account::NewAccount::new(multisig_account_id.clone()).with_uaid(uaid);
    Register::account(register_account)
        .execute(authority, state_transaction)
        .map_err(ValidationFail::InstructionFailed)?;
    let updated_account = rekey_multisig_account(
        state_transaction,
        &multisig_account_id,
        home_domain.as_ref(),
        &spec,
    )
    .map_err(ValidationFail::InstructionFailed)?;
    persist_multisig_account_state(
        state_transaction,
        None,
        &MultisigAccountState::new(updated_account.clone(), home_domain.clone(), spec.clone()),
    )?;
    let role_owner = if let Some(home_domain) = home_domain.as_ref() {
        domain_owner(state_transaction, home_domain)?
    } else {
        updated_account.clone()
    };
    materialize_missing_signatory_accounts(
        state_transaction,
        home_domain.as_ref(),
        &updated_account,
        &spec,
    )?;
    configure_roles(
        state_transaction,
        &role_owner,
        home_domain.as_ref(),
        &updated_account,
        &spec,
    )?;
    Ok(())
}
fn execute_propose(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &MultisigPropose,
) -> Result<(), ValidationFail> {
    let proposer = authority.clone();
    let multisig_account = match resolve_signatory_account(state_transaction, &instruction.account)
    {
        Ok(value) => value,
        Err(err) => {
            iroha_logger::error!(
                proposer = %proposer,
                requested_multisig_account = %instruction.account,
                error = ?err,
                "multisig propose failed to resolve multisig account"
            );
            return Err(err);
        }
    };
    let home_domain = match multisig_home_domain(state_transaction, &multisig_account) {
        Ok(value) => value,
        Err(err) => {
            iroha_logger::error!(
                proposer = %proposer,
                multisig_account = %multisig_account,
                error = ?err,
                "multisig propose failed to load multisig home domain"
            );
            return Err(err);
        }
    };
    let instructions_hash = HashOf::new(&instruction.instructions);
    let multisig_spec = match multisig_spec(state_transaction, &multisig_account) {
        Ok(value) => value,
        Err(err) => {
            iroha_logger::error!(
                proposer = %proposer,
                multisig_account = %multisig_account,
                instructions_hash = %instructions_hash,
                error = ?err,
                "multisig propose failed to load multisig spec"
            );
            return Err(err);
        }
    };
    let home_domain_literal = home_domain
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "-".to_owned());
    iroha_logger::info!(
        proposer = %proposer,
        multisig_account = %multisig_account,
        instructions_hash = %instructions_hash,
        instruction_count = instruction.instructions.len(),
        home_domain = %home_domain_literal,
        quorum = multisig_spec.quorum.get(),
        ttl_ms = multisig_spec.transaction_ttl_ms.get(),
        signatory_count = multisig_spec.signatories.len(),
        "multisig propose evaluating proposal"
    );
    let proposer_role = multisig_role_for(home_domain.as_ref(), &proposer);
    let multisig_role = multisig_role_for(home_domain.as_ref(), &multisig_account);
    let is_downward_proposal = state_transaction
        .world
        .account_roles_iter(&multisig_account)
        .any(|role| role == &proposer_role);
    let has_multisig_role = state_transaction
        .world
        .account_roles_iter(&proposer)
        .any(|role| role == &multisig_role);
    let is_signatory = spec_contains_signatory_subject(&multisig_spec, &proposer);
    let is_self_proposal = proposer.subject_id() == multisig_account.subject_id();
    let has_not_longer_ttl = instruction
        .transaction_ttl_ms
        .is_none_or(|override_ttl_ms| override_ttl_ms <= multisig_spec.transaction_ttl_ms);
    if !has_not_longer_ttl {
        iroha_logger::error!(
            proposer = %proposer,
            multisig_account = %multisig_account,
            instructions_hash = %instructions_hash,
            requested_ttl_ms = ?instruction.transaction_ttl_ms,
            spec_ttl_ms = multisig_spec.transaction_ttl_ms.get(),
            "multisig propose rejected because ttl exceeds multisig spec"
        );
        return Err(ValidationFail::NotPermitted(
            "ttl violates the restriction".to_owned(),
        ));
    }
    if !(is_downward_proposal || has_multisig_role || is_signatory || is_self_proposal) {
        iroha_logger::error!(
            proposer = %proposer,
            multisig_account = %multisig_account,
            instructions_hash = %instructions_hash,
            proposer_role = ?proposer_role,
            multisig_role = ?multisig_role,
            is_downward_proposal,
            has_multisig_role,
            is_signatory,
            is_self_proposal,
            "multisig propose rejected because proposer is not authorized"
        );
        return Err(ValidationFail::NotPermitted(
            "not qualified to propose multisig".to_owned(),
        ));
    }
    let existing_proposal =
        match proposal_state(state_transaction, &multisig_account, &instructions_hash) {
            Ok(existing) if now_ms(state_transaction) < existing.expires_at_ms => {
                iroha_logger::warn!(
                    proposer = %proposer,
                    multisig_account = %multisig_account,
                    instructions_hash = %instructions_hash,
                    now_ms = now_ms(state_transaction),
                    expires_at_ms = existing.expires_at_ms,
                    "multisig propose rejected as duplicate active proposal"
                );
                return Err(ValidationFail::NotPermitted(
                    "multisig proposal duplicates".to_owned(),
                ));
            }
            Ok(_) => true,
            Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound)) => false,
            Err(err) => {
                iroha_logger::error!(
                    proposer = %proposer,
                    multisig_account = %multisig_account,
                    instructions_hash = %instructions_hash,
                    error = ?err,
                    "multisig propose failed while checking existing proposal state"
                );
                return Err(err);
            }
        };
    let now_ms = now_ms(state_transaction);
    if existing_proposal {
        if let Err(err) = prune_expired(
            state_transaction,
            &multisig_account,
            &instructions_hash,
            &instruction.account,
        ) {
            iroha_logger::error!(
                proposer = %proposer,
                multisig_account = %multisig_account,
                instructions_hash = %instructions_hash,
                error = ?err,
                "multisig propose failed while pruning expired proposal state"
            );
            return Err(err);
        }
    }
    // Terminal proposal identity is permanent. Reusing its instruction hash
    // would make historical cancellation and execution evidence ambiguous.
    if state_transaction
        .world
        .smart_contract_state
        .get(&multisig_proposal_terminal_state_key(
            &multisig_account,
            &instructions_hash,
        ))
        .is_some()
    {
        return Err(ValidationFail::NotPermitted(
            "multisig proposal instruction identity is already terminal".to_owned(),
        ));
    }
    let expires_at_ms = {
        let ttl_ms = instruction
            .transaction_ttl_ms
            .unwrap_or(multisig_spec.transaction_ttl_ms);
        now_ms.saturating_add(ttl_ms.into())
    };
    let proposal_value = MultisigProposalValue::new(
        instruction.instructions.clone(),
        now_ms,
        expires_at_ms,
        BTreeSet::from([proposer.clone()]),
        None,
    );
    let approve_me = MultisigApprove::new(multisig_account.clone(), instructions_hash);
    let resolved_signatories = match resolved_signatory_accounts(state_transaction, &multisig_spec)
    {
        Ok(value) => value,
        Err(err) => {
            iroha_logger::error!(
                proposer = %proposer,
                multisig_account = %multisig_account,
                instructions_hash = %instructions_hash,
                error = ?err,
                "multisig propose failed to resolve signatory accounts"
            );
            return Err(err);
        }
    };
    let resolved_signatory_summary = resolved_signatories
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    iroha_logger::info!(
        proposer = %proposer,
        multisig_account = %multisig_account,
        instructions_hash = %instructions_hash,
        resolved_signatory_count = resolved_signatories.len(),
        resolved_signatories = %resolved_signatory_summary,
        "multisig propose resolved signatory accounts"
    );
    for signatory in resolved_signatories {
        let signatory_is_multisig = match is_multisig(state_transaction, &signatory) {
            Ok(value) => value,
            Err(err) => {
                iroha_logger::error!(
                    proposer = %proposer,
                    multisig_account = %multisig_account,
                    instructions_hash = %instructions_hash,
                    signatory = %signatory,
                    error = ?err,
                    "multisig propose failed while checking signatory multisig state"
                );
                return Err(err);
            }
        };
        if signatory_is_multisig
            && let Err(err) = deploy_relayer(
                state_transaction,
                &signatory,
                &approve_me,
                now_ms,
                expires_at_ms,
            )
        {
            iroha_logger::error!(
                proposer = %proposer,
                multisig_account = %multisig_account,
                instructions_hash = %instructions_hash,
                relayer = %signatory,
                error = ?err,
                "multisig propose failed to deploy nested multisig relayer"
            );
            return Err(err);
        }
    }
    let proposal_state = MultisigProposalState::new(
        multisig_account,
        instructions_hash,
        proposal_value.instructions,
        proposal_value.proposed_at_ms,
        proposal_value.expires_at_ms,
        proposal_value.approvals,
        proposal_value.is_relayed,
    );
    match store_multisig_proposal_state(state_transaction, &proposal_state) {
        Ok(()) => {
            iroha_logger::info!(
                proposer = %proposer,
                multisig_account = %proposal_state.multisig_account_id,
                instructions_hash = %proposal_state.instructions_hash,
                proposed_at_ms = proposal_state.proposed_at_ms,
                expires_at_ms = proposal_state.expires_at_ms,
                approvals = proposal_state.approvals.len(),
                "multisig propose stored proposal state"
            );
            Ok(())
        }
        Err(err) => {
            iroha_logger::error!(
                proposer = %proposer,
                multisig_account = %proposal_state.multisig_account_id,
                instructions_hash = %proposal_state.instructions_hash,
                error = ?err,
                "multisig propose failed to store proposal state"
            );
            Err(err)
        }
    }
}
fn execute_approve(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &MultisigApprove,
) -> Result<(), ValidationFail> {
    let approver = authority.clone();
    let multisig_account = resolve_signatory_account(state_transaction, &instruction.account)?;
    let home_domain = multisig_home_domain(state_transaction, &multisig_account)?;
    let instructions_hash = instruction.instructions_hash;
    let spec = multisig_spec(state_transaction, &multisig_account)?;
    let has_multisig_role = state_transaction
        .world
        .account_roles_iter(&approver)
        .any(|role| role == &multisig_role_for(home_domain.as_ref(), &multisig_account));
    let is_signatory = spec_contains_signatory_subject(&spec, &approver);
    let is_self_approval = approver.subject_id() == multisig_account.subject_id();
    if !(has_multisig_role || is_signatory || is_self_approval) {
        return Err(ValidationFail::NotPermitted(
            "not qualified to approve multisig".to_owned(),
        ));
    }
    if let Err(err) = prune_expired(
        state_transaction,
        &multisig_account,
        &instructions_hash,
        &instruction.account,
    ) {
        iroha_logger::error!(
            multisig_account = %multisig_account,
            instructions_hash = %instructions_hash,
            approver = %authority,
            error = ?err,
            "multisig approval proposal lookup failed before approval"
        );
        return Err(err);
    }
    let mut proposal_state = match proposal_state(
        state_transaction,
        &multisig_account,
        &instructions_hash,
    ) {
        Ok(proposal) => proposal,
        Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound)) => {
            store_multisig_approval_outcome(
                state_transaction,
                &instruction.account,
                &multisig_account,
                &instructions_hash,
                MultisigApprovalOutcomeStatusV1::NotExecuted,
            )?;
            let log = Log::new(
                Level::INFO,
                format!(
                    "multisig proposal expired:\naccount: {multisig_account}\ninstructions hash: {instructions_hash}"
                ),
            );
            return log
                .execute(&multisig_account, state_transaction)
                .map_err(ValidationFail::InstructionFailed);
        }
        Err(error) => return Err(error),
    };
    if let Some(true) = proposal_state.is_relayed {
        store_multisig_approval_outcome(
            state_transaction,
            &instruction.account,
            &multisig_account,
            &instructions_hash,
            MultisigApprovalOutcomeStatusV1::NotExecuted,
        )?;
        return Ok(());
    }
    upsert_subject_approval(&mut proposal_state.approvals, approver);
    let approved_weight = approved_weight_by_subject(&spec, &proposal_state.approvals);
    let is_authenticated = approved_weight >= u32::from(spec.quorum.get());
    iroha_logger::info!(
        multisig_account = %multisig_account,
        instructions_hash = %instructions_hash,
        approved_weight,
        quorum = u32::from(spec.quorum.get()),
        is_authenticated,
        "multisig approval evaluated quorum"
    );
    if !is_authenticated {
        iroha_logger::info!(
            multisig_account = %multisig_account,
            instructions_hash = %instructions_hash,
            approvals = proposal_state.approvals.len(),
            "multisig approval storing updated proposal state"
        );
        store_multisig_proposal_state(state_transaction, &proposal_state)?;
        store_multisig_approval_outcome(
            state_transaction,
            &instruction.account,
            &multisig_account,
            &instructions_hash,
            MultisigApprovalOutcomeStatusV1::NotExecuted,
        )?;
        iroha_logger::info!(
            multisig_account = %multisig_account,
            instructions_hash = %instructions_hash,
            "multisig approval stored updated proposal state"
        );
        return Ok(());
    }
    if is_authenticated {
        crate::validation_fee::enforce_deferred_instruction_list(
            &multisig_account,
            proposal_state.instructions.as_slice(),
            state_transaction,
        )
        .map_err(|reason| ValidationFail::NotPermitted(reason.to_string()))?;
        let execution_id = (multisig_account.clone(), instructions_hash);
        begin_multisig_deferred_execution(
            &mut state_transaction.multisig_deferred_execution_stack,
            &execution_id,
        )?;
        let executor = state_transaction.world.executor.clone();
        let execution_result = (|| {
            match proposal_state.is_relayed {
                None => {
                    iroha_logger::info!(
                        multisig_account = %multisig_account,
                        instructions_hash = %instructions_hash,
                        "multisig approval pruning proposal tree"
                    );
                    maybe_store_terminal_proposal_state(
                        state_transaction,
                        &proposal_state,
                        MultisigProposalTerminalStatus::Finalized,
                        &instruction.account,
                    )?;
                    prune_down(state_transaction, &multisig_account, &instructions_hash)?;
                    iroha_logger::info!(
                        multisig_account = %multisig_account,
                        instructions_hash = %instructions_hash,
                        "multisig approval pruned proposal tree"
                    );
                }
                Some(false) => {
                    proposal_state.is_relayed = Some(true);
                    maybe_store_relayed_proposal_execution_state(
                        state_transaction,
                        &proposal_state,
                        &instruction.account,
                    )?;
                    store_multisig_proposal_state(state_transaction, &proposal_state)?;
                }
                _ => unreachable!("proposal_state.is_relayed checked above"),
            }
            for instruction in proposal_state.instructions {
                let instruction_debug = format!("{instruction:?}");
                iroha_logger::info!(
                    multisig_account = %multisig_account,
                    instructions_hash = %instructions_hash,
                    approver = %authority,
                    instruction = %instruction_debug,
                    "multisig approval executing authenticated instruction"
                );
                if let Err(err) =
                    executor.execute_instruction(state_transaction, &multisig_account, instruction)
                {
                    iroha_logger::error!(
                        multisig_account = %multisig_account,
                        instructions_hash = %instructions_hash,
                        approver = %authority,
                        instruction = %instruction_debug,
                        error = ?err,
                        "multisig approval authenticated instruction failed"
                    );
                    return Err(err);
                }
                iroha_logger::info!(
                    multisig_account = %multisig_account,
                    instructions_hash = %instructions_hash,
                    approver = %authority,
                    "multisig approval finished authenticated instruction"
                );
            }
            store_multisig_approval_outcome(
                state_transaction,
                &instruction.account,
                &multisig_account,
                &instructions_hash,
                MultisigApprovalOutcomeStatusV1::Executed,
            )
        })();
        finish_multisig_deferred_execution(
            &mut state_transaction.multisig_deferred_execution_stack,
            &execution_id,
        );
        execution_result?;
    }
    Ok(())
}
fn canceler_is_authorized(multisig_account: &AccountId, canceler: &AccountId) -> bool {
    canceler.subject_id() == multisig_account.subject_id()
}
fn execute_cancel(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &MultisigCancel,
) -> Result<(), ValidationFail> {
    let canceler = authority.clone();
    let multisig_account = resolve_signatory_account(state_transaction, &instruction.account)?;
    let instructions_hash = instruction.instructions_hash;
    if !canceler_is_authorized(&multisig_account, &canceler) {
        return Err(ValidationFail::NotPermitted(
            "multisig cancel must execute as the multisig account".to_owned(),
        ));
    }
    prune_expired(
        state_transaction,
        &multisig_account,
        &instructions_hash,
        &instruction.account,
    )?;
    let proposal_state = proposal_state(state_transaction, &multisig_account, &instructions_hash)?;
    if let Some(true) = proposal_state.is_relayed {
        return Err(ValidationFail::NotPermitted(
            "cannot cancel an executed relayed approval".to_owned(),
        ));
    }
    maybe_store_terminal_proposal_state(
        state_transaction,
        &proposal_state,
        MultisigProposalTerminalStatus::Canceled,
        &instruction.account,
    )?;
    prune_down(state_transaction, &multisig_account, &instructions_hash)
}
fn execute_invalidate_outstanding(
    state_transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: &MultisigInvalidateOutstanding,
) -> Result<(), ValidationFail> {
    let multisig_account = resolve_signatory_account(state_transaction, &instruction.account)?;
    if !canceler_is_authorized(&multisig_account, authority) {
        return Err(ValidationFail::NotPermitted(
            "multisig outstanding-proposal invalidation must execute as the multisig account"
                .to_owned(),
        ));
    }
    invalidate_outstanding_proposals(state_transaction, &multisig_account).map(|_| ())
}
fn deploy_relayer(
    state_transaction: &mut StateTransaction<'_, '_>,
    relayer: &AccountId,
    relay: &MultisigApprove,
    now_ms: u64,
    parent_expires_at_ms: u64,
) -> Result<(), ValidationFail> {
    let spec = multisig_spec(state_transaction, relayer)?;
    let relay_expires_at_ms =
        capped_relay_expiry(now_ms, parent_expires_at_ms, spec.transaction_ttl_ms.get());
    let relay_hash = HashOf::new(&vec![InstructionBox::from(relay.clone())]);
    let sub_relay = MultisigApprove::new(relayer.clone(), relay_hash);
    for signatory in resolved_signatory_accounts(state_transaction, &spec)? {
        if is_multisig(state_transaction, &signatory)? {
            deploy_relayer(
                state_transaction,
                &signatory,
                &sub_relay,
                now_ms,
                relay_expires_at_ms,
            )?;
        }
    }
    let relay_value = MultisigProposalValue::new(
        vec![InstructionBox::from(relay.clone())],
        now_ms,
        relay_expires_at_ms,
        BTreeSet::new(),
        Some(false),
    );
    store_multisig_proposal_state(
        state_transaction,
        &MultisigProposalState::new(
            relayer.clone(),
            relay_hash,
            relay_value.instructions,
            relay_value.proposed_at_ms,
            relay_value.expires_at_ms,
            relay_value.approvals,
            relay_value.is_relayed,
        ),
    )
}
fn capped_relay_expiry(now_ms: u64, parent_expires_at_ms: u64, relayer_ttl_ms: u64) -> u64 {
    let local_expiry = now_ms.saturating_add(relayer_ttl_ms);
    local_expiry.min(parent_expires_at_ms)
}
fn begin_multisig_deferred_execution(
    execution_stack: &mut Vec<MultisigDeferredExecutionId>,
    execution_id: &MultisigDeferredExecutionId,
) -> Result<(), ValidationFail> {
    if execution_stack.iter().any(|active| active == execution_id) {
        return Err(ValidationFail::NotPermitted(
            "multisig deferred execution contains a proposal cycle".to_owned(),
        ));
    }
    if execution_stack.len() >= MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH {
        return Err(ValidationFail::TooComplex);
    }
    execution_stack.push(execution_id.clone());
    Ok(())
}
fn finish_multisig_deferred_execution(
    execution_stack: &mut Vec<MultisigDeferredExecutionId>,
    execution_id: &MultisigDeferredExecutionId,
) {
    let finished = execution_stack.pop();
    debug_assert_eq!(finished.as_ref(), Some(execution_id));
}
fn prune_expired(
    state_transaction: &mut StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    entrypoint_account: &AccountId,
) -> Result<(), ValidationFail> {
    prune_expired_with_guard(
        state_transaction,
        multisig_account,
        instructions_hash,
        entrypoint_account,
        0,
        &mut BTreeSet::new(),
    )
}
fn prune_expired_with_guard(
    state_transaction: &mut StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    entrypoint_account: &AccountId,
    depth: usize,
    active_path: &mut BTreeSet<MultisigDeferredExecutionId>,
) -> Result<(), ValidationFail> {
    if depth >= MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH {
        return Err(ValidationFail::TooComplex);
    }
    let proposal_state = proposal_state(state_transaction, multisig_account, instructions_hash)?;
    let execution_id = (
        proposal_state.multisig_account_id.clone(),
        proposal_state.instructions_hash,
    );
    if !active_path.insert(execution_id.clone()) {
        return Err(ValidationFail::NotPermitted(
            "multisig proposal expiry traversal contains a cycle".to_owned(),
        ));
    }
    let result = (|| {
        if now_ms(state_transaction) < proposal_state.expires_at_ms {
            return Ok(());
        }
        for instruction in &proposal_state.instructions {
            if let Some(MultisigInstructionBox::Approve(approve)) =
                proposal_instruction_attempt(instruction)
                    .map_err(|error| retain_multisig_read_attempt(state_transaction, error))?
            {
                prune_expired_with_guard(
                    state_transaction,
                    &approve.account,
                    &approve.instructions_hash,
                    &approve.account,
                    depth.saturating_add(1),
                    active_path,
                )?;
            }
        }
        maybe_store_terminal_proposal_state(
            state_transaction,
            &proposal_state,
            MultisigProposalTerminalStatus::Expired,
            entrypoint_account,
        )?;
        prune_down(state_transaction, multisig_account, instructions_hash)
    })();
    active_path.remove(&execution_id);
    result
}
fn prune_down(
    state_transaction: &mut StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> Result<(), ValidationFail> {
    let spec = multisig_spec(state_transaction, multisig_account)?;
    state_transaction
        .world
        .smart_contract_state
        .remove(multisig_proposal_state_key(
            multisig_account,
            instructions_hash,
        ));
    for signatory in resolved_signatory_accounts(state_transaction, &spec)? {
        let relay_hash = {
            let relay = MultisigApprove::new(multisig_account.clone(), *instructions_hash);
            HashOf::new(&vec![InstructionBox::from(relay)])
        };
        if is_multisig(state_transaction, &signatory)? {
            prune_down(state_transaction, &signatory, &relay_hash)?;
        }
    }
    Ok(())
}
fn validate_registration(
    state_transaction: &mut StateTransaction<'_, '_>,
    _multisig_account: &AccountId,
    spec: &MultisigSpec,
) -> Result<(), ValidationFail> {
    ensure_quorum_reachable(spec)?;
    ensure_signatories_are_single(spec)?;
    let roots = spec.signatories.keys().cloned();
    ensure_multisig_graph_is_acyclic(roots, state_transaction)?;
    Ok(())
}
fn ensure_quorum_reachable(spec: &MultisigSpec) -> Result<(), ValidationFail> {
    let total_weight: u32 = spec
        .signatories
        .values()
        .map(|weight| u32::from(*weight))
        .sum();
    let quorum = u32::from(spec.quorum.get());
    if total_weight < quorum {
        return Err(ValidationFail::NotPermitted(format!(
            "multisig quorum {quorum} exceeds total signatory weight {total_weight}"
        )));
    }
    Ok(())
}
fn ensure_signatories_are_single(spec: &MultisigSpec) -> Result<(), ValidationFail> {
    for account in spec.signatories.keys() {
        if account.controller().single_signatory().is_none() {
            return Err(ValidationFail::NotPermitted(format!(
                "multisig signatory `{account}` must be a single-key account"
            )));
        }
    }
    Ok(())
}
fn ensure_multisig_graph_is_acyclic(
    roots: impl IntoIterator<Item = AccountId>,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), ValidationFail> {
    ensure_multisig_graph_is_acyclic_with(roots.into_iter().collect(), |account| {
        if !is_multisig(state_transaction, &account)? {
            return Ok(Vec::new());
        }
        let spec = multisig_spec(state_transaction, &account)?;
        Ok(spec.signatories.keys().cloned().collect())
    })
}
fn spec_contains_signatory_subject(spec: &MultisigSpec, account: &AccountId) -> bool {
    let subject = account.subject_id();
    spec.signatories
        .keys()
        .any(|signatory| signatory.subject_id() == subject)
}
fn approved_weight_by_subject(spec: &MultisigSpec, approvals: &BTreeSet<AccountId>) -> u32 {
    let approved_subjects: BTreeSet<_> = approvals.iter().map(AccountId::subject_id).collect();
    spec.signatories
        .iter()
        .filter(|(signatory, _)| approved_subjects.contains(&signatory.subject_id()))
        .map(|(_, weight)| u32::from(*weight))
        .sum()
}
fn upsert_subject_approval(approvals: &mut BTreeSet<AccountId>, approver: AccountId) {
    let approver_subject = approver.subject_id();
    approvals.retain(|approved| approved.subject_id() != approver_subject);
    approvals.insert(approver);
}
fn resolve_signatory_account(
    state_transaction: &StateTransaction<'_, '_>,
    signatory: &AccountId,
) -> Result<AccountId, ValidationFail> {
    state_transaction
        .world
        .account(signatory)
        .map(|account| account.id().clone())
        .map_err(map_find_error)
}
fn resolve_account_for_instruction(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<AccountId, InstructionExecutionError> {
    resolve_signatory_account(state_transaction, account).map_err(map_validation_fail)
}
fn materialize_missing_signatory_accounts(
    state_transaction: &mut StateTransaction<'_, '_>,
    home_domain: Option<&iroha_model_base::domain::DomainId>,
    multisig_account: &AccountId,
    spec: &MultisigSpec,
) -> Result<(), ValidationFail> {
    let authority = if let Some(home_domain) = home_domain {
        domain_owner(state_transaction, home_domain)?
    } else {
        multisig_account.clone()
    };
    for signatory in spec.signatories.keys() {
        if signatory.subject_id() == multisig_account.subject_id() {
            continue;
        }
        ensure_signatory_account_exists(state_transaction, signatory, &authority, home_domain)?;
    }
    Ok(())
}
fn ensure_signatory_account_exists(
    state_transaction: &mut StateTransaction<'_, '_>,
    signatory: &AccountId,
    authority: &AccountId,
    _home_domain: Option<&iroha_model_base::domain::DomainId>,
) -> Result<(), ValidationFail> {
    match resolve_signatory_account(state_transaction, signatory) {
        Ok(_) => Ok(()),
        Err(ValidationFail::InstructionFailed(InstructionExecutionError::Find(
            FindError::Account(_),
        )))
        | Err(ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::Account(_)))) => {
            let mut metadata = Metadata::default();
            metadata.insert((*MULTISIG_CREATED_VIA_KEY).clone(), Json::new("multisig"));
            let register_account = iroha_data_model::account::NewAccount::new(signatory.clone());
            Register::account(register_account.with_metadata(metadata))
                .execute(authority, state_transaction)
                .map_err(ValidationFail::InstructionFailed)
        }
        Err(err) => Err(err),
    }
}
fn resolved_signatory_accounts(
    state_transaction: &StateTransaction<'_, '_>,
    spec: &MultisigSpec,
) -> Result<Vec<AccountId>, ValidationFail> {
    let mut accounts = Vec::new();
    let mut seen = BTreeSet::new();
    for signatory in spec.signatories.keys() {
        let subject = signatory.subject_id();
        if !seen.insert(subject) {
            continue;
        }
        accounts.push(resolve_signatory_account(state_transaction, signatory)?);
    }
    Ok(accounts)
}
fn ensure_multisig_graph_is_acyclic_with<F>(
    roots: Vec<AccountId>,
    mut next: F,
) -> Result<(), ValidationFail>
where
    F: FnMut(AccountId) -> Result<Vec<AccountId>, ValidationFail>,
{
    let mut stack: Vec<(AccountId, Vec<AccountId>)> = roots
        .into_iter()
        .map(|root| {
            let path = vec![root.clone()];
            (root, path)
        })
        .collect();
    while let Some((current, path)) = stack.pop() {
        let children = next(current.clone())?;
        for child in children {
            if let Some(idx) = path.iter().position(|seen| seen == &child) {
                let mut cycle = path[idx..].to_vec();
                cycle.push(child.clone());
                let message = cycle
                    .into_iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                return Err(ValidationFail::NotPermitted(format!(
                    "multisig spec forms a cycle: {message}"
                )));
            }
            let mut next_path = path.clone();
            next_path.push(child.clone());
            stack.push((child, next_path));
        }
    }
    Ok(())
}
fn multisig_spec(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
) -> Result<MultisigSpec, ValidationFail> {
    Ok(load_multisig_account_state(state_transaction, multisig_account)?.spec)
}
fn is_multisig(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<bool, ValidationFail> {
    match load_multisig_account_state_optional(state_transaction, account) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(ValidationFail::InstructionFailed(InstructionExecutionError::Find(
            FindError::Account(_),
        ))) => Ok(false),
        Err(ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::Account(_)))) => {
            Ok(false)
        }
        Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound)) => Ok(false),
        Err(err) => Err(err),
    }
}
fn domain_owner(
    state_transaction: &StateTransaction<'_, '_>,
    domain_id: &iroha_model_base::domain::DomainId,
) -> Result<AccountId, ValidationFail> {
    state_transaction
        .world
        .domain(domain_id)
        .map(|domain| domain.owned_by().clone())
        .map_err(map_find_error)
}
fn account_exists(
    state_transaction: &StateTransaction<'_, '_>,
    account_id: &AccountId,
) -> Result<bool, ValidationFail> {
    match state_transaction.world.account(account_id) {
        Ok(_) => Ok(true),
        Err(FindError::Account(_)) => Ok(false),
        Err(err) => Err(map_find_error(err)),
    }
}
fn configure_roles(
    state_transaction: &mut StateTransaction<'_, '_>,
    role_owner: &AccountId,
    home_domain: Option<&iroha_model_base::domain::DomainId>,
    multisig_account: &AccountId,
    spec: &MultisigSpec,
) -> Result<(), ValidationFail> {
    let signatories = resolved_signatory_accounts(state_transaction, spec)?;
    let multisig_role_id = multisig_role_for(home_domain, multisig_account);
    ensure_role_available(
        state_transaction,
        role_owner,
        &multisig_role_id,
        &signatories,
    )?;
    grant_role_if_needed(
        state_transaction,
        &multisig_role_id,
        multisig_account,
        role_owner,
    )?;
    for signatory in &signatories {
        let signatory_role_id = multisig_role_for(home_domain, signatory);
        let delegates = [signatory.clone(), multisig_account.clone()];
        ensure_role_available(
            state_transaction,
            role_owner,
            &signatory_role_id,
            &delegates,
        )?;
        grant_role_if_needed(state_transaction, &signatory_role_id, signatory, role_owner)?;
        grant_role_if_needed(
            state_transaction,
            &signatory_role_id,
            multisig_account,
            role_owner,
        )?;
        grant_role_if_needed(state_transaction, &multisig_role_id, signatory, role_owner)?;
    }
    Ok(())
}
fn multisig_spec_strict(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
) -> Result<MultisigSpec, InstructionExecutionError> {
    load_multisig_account_state(state_transaction, multisig_account)
        .map(|state| state.spec)
        .map_err(map_validation_fail)
}
fn multisig_home_domain(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
) -> Result<Option<iroha_model_base::domain::DomainId>, ValidationFail> {
    Ok(load_multisig_account_state(state_transaction, multisig_account)?.home_domain)
}
fn ensure_role_available(
    state_transaction: &mut StateTransaction<'_, '_>,
    domain_owner: &AccountId,
    role_id: &RoleId,
    delegates: &[AccountId],
) -> Result<(), ValidationFail> {
    if !role_exists(state_transaction, role_id) {
        Register::role(Role::new(role_id.clone(), domain_owner.clone()))
            .execute(domain_owner, state_transaction)
            .map_err(ValidationFail::InstructionFailed)?;
        return Ok(());
    }
    if has_role(state_transaction, domain_owner, role_id)? {
        return Ok(());
    }
    for delegate in delegates {
        if delegate == domain_owner || !has_role(state_transaction, delegate, role_id)? {
            continue;
        }
        Grant::account_role(role_id.clone(), domain_owner.clone())
            .execute(delegate, state_transaction)
            .map_err(ValidationFail::InstructionFailed)?;
        if has_role(state_transaction, domain_owner, role_id)? {
            return Ok(());
        }
    }
    Err(ValidationFail::NotPermitted(format!(
        "domain owner `{domain_owner}` must hold role `{role_id}` to configure multisig"
    )))
}
fn grant_role_if_needed(
    state_transaction: &mut StateTransaction<'_, '_>,
    role_id: &RoleId,
    account: &AccountId,
    authority: &AccountId,
) -> Result<(), ValidationFail> {
    if has_role(state_transaction, account, role_id)? {
        return Ok(());
    }
    Grant::account_role(role_id.clone(), account.clone())
        .execute(authority, state_transaction)
        .map_err(ValidationFail::InstructionFailed)
}
fn has_role(
    state_transaction: &StateTransaction<'_, '_>,
    account: &AccountId,
    role_id: &RoleId,
) -> Result<bool, ValidationFail> {
    let resolved_account = match resolve_signatory_account(state_transaction, account) {
        Ok(account) => account,
        Err(ValidationFail::InstructionFailed(InstructionExecutionError::Find(
            FindError::Account(_),
        )))
        | Err(ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::Account(_)))) => {
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    state_transaction
        .world
        .account(&resolved_account)
        .map_err(map_find_error)?;
    Ok(state_transaction
        .world
        .account_roles_iter(&resolved_account)
        .any(|role| role == role_id))
}
fn role_exists(state_transaction: &StateTransaction<'_, '_>, role_id: &RoleId) -> bool {
    state_transaction.world.roles.get(role_id).is_some()
}
fn persist_multisig_account_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    previous_account_state: Option<&MultisigAccountState>,
    account_state: &MultisigAccountState,
) -> Result<(), ValidationFail> {
    let account = state_transaction
        .world
        .accounts
        .get_mut(&account_state.account_id)
        .ok_or_else(|| {
            ValidationFail::InstructionFailed(InstructionExecutionError::Find(FindError::Account(
                account_state.account_id.clone(),
            )))
        })?;
    account
        .metadata
        .insert(spec_key(), Json::new(account_state.spec.clone()));
    account.metadata.insert(
        home_domain_key(),
        Json::new(account_state.home_domain.clone()),
    );
    let bytes = norito::to_bytes(account_state).map_err(multisig_state_encode_error)?;
    state_transaction
        .world
        .smart_contract_state
        .insert(multisig_account_state_key(&account_state.account_id), bytes);
    sync_multisig_signatory_index(
        state_transaction,
        previous_account_state,
        Some(account_state),
    )?;
    Ok(())
}
fn multisig_signatory_index_members(account_state: &MultisigAccountState) -> BTreeSet<AccountId> {
    account_state
        .spec
        .signatories
        .keys()
        .map(AccountId::subject_id)
        .collect()
}
fn load_multisig_signatory_memberships(
    state_transaction: &StateTransaction<'_, '_>,
    signatory: &AccountId,
) -> Result<BTreeSet<AccountId>, ValidationFail> {
    let key = multisig_signatory_index_key(signatory);
    let Some(bytes) = state_transaction.world.smart_contract_state.get(&key) else {
        return Ok(BTreeSet::new());
    };
    norito::decode_from_bytes(bytes).map_err(multisig_state_decode_error)
}
fn store_multisig_signatory_memberships(
    state_transaction: &mut StateTransaction<'_, '_>,
    signatory: &AccountId,
    memberships: &BTreeSet<AccountId>,
) -> Result<(), ValidationFail> {
    let key = multisig_signatory_index_key(signatory);
    if memberships.is_empty() {
        state_transaction.world.smart_contract_state.remove(key);
        return Ok(());
    }
    let bytes = norito::to_bytes(memberships).map_err(multisig_state_encode_error)?;
    state_transaction
        .world
        .smart_contract_state
        .insert(key, bytes);
    Ok(())
}
fn sync_multisig_signatory_index(
    state_transaction: &mut StateTransaction<'_, '_>,
    previous_account_state: Option<&MultisigAccountState>,
    next_account_state: Option<&MultisigAccountState>,
) -> Result<(), ValidationFail> {
    let removed_members = previous_account_state
        .map(multisig_signatory_index_members)
        .unwrap_or_default();
    let added_members = next_account_state
        .map(multisig_signatory_index_members)
        .unwrap_or_default();
    let previous_multisig_account_id = previous_account_state.map(|state| state.account_id.clone());
    let next_multisig_account_id = next_account_state.map(|state| state.account_id.clone());
    let member_ids: BTreeSet<_> = removed_members
        .iter()
        .chain(added_members.iter())
        .cloned()
        .collect();
    for signatory in member_ids {
        let mut memberships = load_multisig_signatory_memberships(state_transaction, &signatory)?;
        if let Some(previous_multisig_account_id) = previous_multisig_account_id.as_ref()
            && removed_members.contains(&signatory)
        {
            memberships.remove(previous_multisig_account_id);
        }
        if let Some(next_multisig_account_id) = next_multisig_account_id.as_ref()
            && added_members.contains(&signatory)
        {
            memberships.insert(next_multisig_account_id.clone());
        }
        store_multisig_signatory_memberships(state_transaction, &signatory, &memberships)?;
    }
    Ok(())
}
fn load_multisig_account_state_optional(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
) -> Result<Option<MultisigAccountState>, ValidationFail> {
    let resolved_account = resolve_signatory_account(state_transaction, multisig_account)?;
    read_registered_account_state(&state_transaction.world, &resolved_account)
        .map_err(|error| retain_multisig_read_attempt(state_transaction, error))
}
fn load_multisig_account_state(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
) -> Result<MultisigAccountState, ValidationFail> {
    load_multisig_account_state_optional(state_transaction, multisig_account)?
        .ok_or(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
}
fn store_multisig_proposal_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal_state: &MultisigProposalState,
) -> Result<(), ValidationFail> {
    let bytes = norito::to_bytes(proposal_state).map_err(multisig_state_encode_error)?;
    state_transaction.world.smart_contract_state.insert(
        multisig_proposal_state_key(
            &proposal_state.multisig_account_id,
            &proposal_state.instructions_hash,
        ),
        bytes,
    );
    Ok(())
}
fn store_multisig_proposal_terminal_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    terminal_state: &MultisigProposalTerminalState,
) -> Result<(), ValidationFail> {
    let bytes = norito::to_bytes(terminal_state).map_err(multisig_state_encode_error)?;
    let key = multisig_proposal_terminal_state_key(
        &terminal_state.multisig_account_id,
        &terminal_state.instructions_hash,
    );
    if let Some(existing) = state_transaction.world.smart_contract_state.get(&key) {
        if existing != &bytes {
            return Err(ValidationFail::InternalError(
                "conflicting immutable multisig terminal proposal state".into(),
            ));
        }
        return Ok(());
    }
    state_transaction
        .world
        .smart_contract_state
        .insert(key, bytes);
    Ok(())
}
fn store_multisig_proposal_terminal_execution_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    terminal_state: &MultisigProposalTerminalState,
    entrypoint_account: &AccountId,
) -> Result<(), ValidationFail> {
    let Some(terminal_entrypoint_hash) = state_transaction
        .tx_call_hash
        .as_ref()
        .map(|hash| *hash.as_ref())
    else {
        // Some unit-level execution helpers do not install a transaction call hash. There is no
        // transaction identity to bind immutable evidence to in that context.
        return Ok(());
    };
    let execution_state = MultisigProposalTerminalExecutionStateV1::new(
        terminal_state.clone(),
        entrypoint_account.clone(),
        state_transaction.block_height(),
        terminal_entrypoint_hash,
    );
    let bytes = norito::to_bytes(&execution_state).map_err(multisig_state_encode_error)?;
    let execution_key = multisig_proposal_terminal_execution_state_key(
        terminal_entrypoint_hash,
        entrypoint_account,
        &terminal_state.instructions_hash,
    );
    if let Some(existing) = state_transaction
        .world
        .smart_contract_state
        .get(&execution_key)
    {
        if existing.as_slice() != bytes {
            return Err(ValidationFail::InternalError(format!(
                "conflicting immutable multisig terminal execution state at `{execution_key}`"
            )));
        }
    } else {
        state_transaction
            .world
            .smart_contract_state
            .insert(execution_key, bytes);
    }
    Ok(())
}
fn store_multisig_approval_outcome(
    state_transaction: &mut StateTransaction<'_, '_>,
    entrypoint_account: &AccountId,
    resolved_multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
    status: MultisigApprovalOutcomeStatusV1,
) -> Result<(), ValidationFail> {
    let Some(entrypoint_hash) = state_transaction
        .tx_call_hash
        .as_ref()
        .map(|hash| *hash.as_ref())
    else {
        // Unit-level helpers without a transaction identity cannot emit durable approval evidence.
        return Ok(());
    };
    let outcome = MultisigApprovalOutcomeV1::new(
        entrypoint_account.clone(),
        resolved_multisig_account.clone(),
        *instructions_hash,
        status,
        state_transaction.block_height(),
        entrypoint_hash,
    );
    let bytes = norito::to_bytes(&outcome).map_err(multisig_state_encode_error)?;
    let outcome_key =
        multisig_approval_outcome_state_key(entrypoint_hash, entrypoint_account, instructions_hash);
    if let Some(existing) = state_transaction
        .world
        .smart_contract_state
        .get(&outcome_key)
    {
        if existing.as_slice() != bytes {
            return Err(ValidationFail::InternalError(format!(
                "conflicting immutable multisig approval outcome at `{outcome_key}`"
            )));
        }
    } else {
        state_transaction
            .world
            .smart_contract_state
            .insert(outcome_key, bytes);
    }
    Ok(())
}
fn proposal_state(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> Result<MultisigProposalState, ValidationFail> {
    proposal_state_attempt(state_transaction, multisig_account, instructions_hash)
        .map_err(|error| retain_multisig_read_attempt(state_transaction, error))
}

fn retain_multisig_read_attempt(
    state_transaction: &StateTransaction<'_, '_>,
    error: Attempt<ValidationFail>,
) -> ValidationFail {
    match error {
        Attempt::Rejected(error) => error,
        Attempt::Deferred(reason) => state_transaction.world.defer_execution(reason),
    }
}

fn multisig_decode_attempt(error: norito::Error) -> Attempt<ValidationFail> {
    if cfg!(all(test, sumeragi_core_mutation = "HC67")) {
        return Attempt::Rejected(multisig_state_decode_error(error));
    }
    norito_decode_attempt_error(error, multisig_state_decode_error)
}

fn proposal_state_attempt(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> Result<MultisigProposalState, Attempt<ValidationFail>> {
    let resolved_account = resolve_signatory_account(state_transaction, multisig_account)?;
    read_proposal_state(
        &state_transaction.world,
        &resolved_account,
        instructions_hash,
    )?
    .ok_or_else(|| ValidationFail::QueryFailed(QueryExecutionFail::NotFound).into())
}

/// Read the exact authenticated proposal used by execution and queue admission.
///
/// Only a missing physical row is `None`. A retained body must reproduce the hash that the
/// signatories approved; malformed bindings reject, while unfinished local reads remain deferred.
pub(crate) fn read_proposal_state<W: WorldReadOnly>(
    world: &W,
    account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> Result<Option<MultisigProposalState>, Attempt<ValidationFail>> {
    let key = multisig_proposal_state_key(account, instructions_hash);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let proposal = decode_proposal_state_at_key(&key, bytes)?;
    if proposal.multisig_account_id != *account || proposal.instructions_hash != *instructions_hash
    {
        return Err(invalid_proposal_binding().into());
    }
    Ok(Some(proposal))
}

fn invalid_proposal_binding() -> ValidationFail {
    ValidationFail::QueryFailed(QueryExecutionFail::Conversion(
        "native multisig proposal does not match its exact account and instruction-hash key or approved body"
            .into(),
    ))
}

fn decode_proposal_state_at_key(
    key: &StatePath,
    bytes: &[u8],
) -> Result<MultisigProposalState, Attempt<ValidationFail>> {
    let proposal = norito::decode_from_bytes::<MultisigProposalState>(bytes)
        .map_err(multisig_decode_attempt)?;
    // Stream the existing V1 hash domain, retaining original serializer refusal. Never buffer
    // a second encoded proposal or rewrite an inconsistent row to fit its lookup key.
    let hash = HashOf::try_new(&proposal.instructions)
        .map_err(|error| multisig_instruction_decode_attempt(error, multisig_state_encode_error))?;
    if !cfg!(all(test, sumeragi_core_mutation = "HC68"))
        && (proposal.instructions_hash != hash
            || *key != multisig_proposal_state_key(&proposal.multisig_account_id, &hash))
    {
        return Err(invalid_proposal_binding().into());
    }
    Ok(proposal)
}

/// Validate retained native proposal rows before a restored World can become visible.
pub(crate) fn validate_persisted_proposals<W: WorldReadOnly>(
    world: &W,
) -> Result<(), Attempt<ValidationFail>> {
    let prefix: StatePath = "multisig/proposal/".parse().expect("constant state prefix");
    for (key, bytes) in world.smart_contract_state().range(prefix.clone()..) {
        if !key.as_ref().starts_with(prefix.as_ref()) {
            break;
        }
        decode_proposal_state_at_key(key, bytes)?;
    }
    Ok(())
}

fn proposal_instruction_attempt(
    instruction: &InstructionBox,
) -> Result<Option<MultisigInstructionBox>, Attempt<ValidationFail>> {
    match MultisigInstructionBox::try_from(instruction) {
        Ok(instruction) => Ok(Some(instruction)),
        Err(error) => match multisig_instruction_decode_attempt(error, multisig_state_decode_error)
        {
            Attempt::Deferred(reason) if !cfg!(all(test, sumeragi_core_mutation = "HC69")) => {
                Err(Attempt::Deferred(reason))
            }
            // Non-multisig instructions are valid proposal contents. Only a completed decode
            // can determine that; an original local refusal cannot become a nonmatch.
            _ => Ok(None),
        },
    }
}
fn proposal_state_value(proposal_state: &MultisigProposalState) -> MultisigProposalValue {
    MultisigProposalValue::new(
        proposal_state.instructions.clone(),
        proposal_state.proposed_at_ms,
        proposal_state.expires_at_ms,
        proposal_state.approvals.clone(),
        proposal_state.is_relayed,
    )
}
fn proposal_is_cancel_wrapper(
    proposal_state: &MultisigProposalState,
) -> Result<bool, Attempt<ValidationFail>> {
    let [instruction] = proposal_state.instructions.as_slice() else {
        return Ok(false);
    };
    Ok(matches!(
        proposal_instruction_attempt(instruction)?,
        Some(MultisigInstructionBox::Cancel(_))
    ))
}
fn maybe_store_terminal_proposal_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal_state: &MultisigProposalState,
    status: MultisigProposalTerminalStatus,
    entrypoint_account: &AccountId,
) -> Result<(), ValidationFail> {
    if proposal_state.is_relayed.is_some()
        || proposal_is_cancel_wrapper(proposal_state)
            .map_err(|error| retain_multisig_read_attempt(state_transaction, error))?
    {
        return Ok(());
    }
    let terminal_state = MultisigProposalTerminalState::new(
        proposal_state.multisig_account_id.clone(),
        proposal_state.instructions_hash,
        proposal_state_value(proposal_state),
        status,
        now_ms(state_transaction),
    );
    store_multisig_proposal_terminal_execution_state(
        state_transaction,
        &terminal_state,
        entrypoint_account,
    )?;
    store_multisig_proposal_terminal_state(state_transaction, &terminal_state)
}
fn maybe_store_relayed_proposal_execution_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    proposal_state: &MultisigProposalState,
    entrypoint_account: &AccountId,
) -> Result<(), ValidationFail> {
    debug_assert_eq!(proposal_state.is_relayed, Some(true));
    let terminal_state = MultisigProposalTerminalState::new(
        proposal_state.multisig_account_id.clone(),
        proposal_state.instructions_hash,
        proposal_state_value(proposal_state),
        MultisigProposalTerminalStatus::Finalized,
        now_ms(state_transaction),
    );
    store_multisig_proposal_terminal_execution_state(
        state_transaction,
        &terminal_state,
        entrypoint_account,
    )
}
fn move_multisig_proposals(
    state_transaction: &mut StateTransaction<'_, '_>,
    old_account: &AccountId,
    new_account: &AccountId,
) -> Result<(), ValidationFail> {
    let prefix = multisig_proposal_state_prefix(old_account);
    let prefix_literal = prefix.as_ref().to_owned();
    let mut entries = Vec::new();
    for (key, value) in state_transaction
        .world
        .smart_contract_state
        .range(prefix.clone()..)
    {
        if !key.as_ref().starts_with(prefix_literal.as_str()) {
            break;
        }
        let state = decode_proposal_state_at_key(key, value)
            .map_err(|error| retain_multisig_read_attempt(state_transaction, error))?;
        let new_key = multisig_proposal_state_key(new_account, &state.instructions_hash);
        if state_transaction
            .world
            .smart_contract_state
            .get(&new_key)
            .is_some()
        {
            return Err(ValidationFail::NotPermitted(
                "multisig rekey cannot overwrite an existing destination proposal".into(),
            ));
        }
        entries.push((key.clone(), state));
    }
    for (old_key, mut proposal_state) in entries {
        proposal_state.multisig_account_id = new_account.clone();
        store_multisig_proposal_state(state_transaction, &proposal_state)?;
        state_transaction.world.smart_contract_state.remove(old_key);
    }
    // Terminal records retain their original policy identity and approvals.
    // Rekey cannot rewrite history or fabricate a new execution witness.
    Ok(())
}
/// Cancel every outstanding native multisig proposal owned by `account`.
///
/// Account recovery calls this immediately before replacing a controller, and
/// [`MultisigInvalidateOutstanding`] exposes the same behavior as a deliberate
/// owner-authorized policy-change instruction. When both instructions share a
/// state transaction, rekey can never migrate a still-actionable proposal to
/// the replacement signer set. The returned hashes are stable terminal
/// evidence. Executed relays (`is_relayed == Some(true)`) are historical rather
/// than outstanding and are intentionally left for the ordinary rekey mover.
pub(crate) fn invalidate_outstanding_proposals(
    state_transaction: &mut StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<Vec<HashOf<Vec<InstructionBox>>>, ValidationFail> {
    let prefix = multisig_proposal_state_prefix(account);
    let prefix_literal = prefix.as_ref().to_owned();
    let mut proposals = Vec::new();
    for (key, value) in state_transaction
        .world
        .smart_contract_state
        .range(prefix.clone()..)
    {
        if !key.as_ref().starts_with(prefix_literal.as_str()) {
            break;
        }
        let state = decode_proposal_state_at_key(key, value)
            .map_err(|error| retain_multisig_read_attempt(state_transaction, error))?;
        if state.is_relayed != Some(true) {
            proposals.push(state);
        }
    }
    proposals.sort_by_key(|proposal| proposal.instructions_hash);
    let mut invalidated = Vec::with_capacity(proposals.len());
    for proposal in proposals {
        let proposal_key =
            multisig_proposal_state_key(&proposal.multisig_account_id, &proposal.instructions_hash);
        if state_transaction
            .world
            .smart_contract_state
            .get(&proposal_key)
            .is_none()
        {
            // A prior top-level cancellation may already have pruned this
            // nested relay. Its parent hash is the authoritative evidence.
            continue;
        }
        let terminal_status = if now_ms(state_transaction) >= proposal.expires_at_ms {
            MultisigProposalTerminalStatus::Expired
        } else {
            MultisigProposalTerminalStatus::Canceled
        };
        let terminal_state = MultisigProposalTerminalState::new(
            proposal.multisig_account_id.clone(),
            proposal.instructions_hash,
            proposal_state_value(&proposal),
            terminal_status,
            now_ms(state_transaction),
        );
        store_multisig_proposal_terminal_execution_state(
            state_transaction,
            &terminal_state,
            account,
        )?;
        store_multisig_proposal_terminal_state(state_transaction, &terminal_state)?;
        invalidated.push(proposal.instructions_hash);
        prune_down(
            state_transaction,
            &proposal.multisig_account_id,
            &proposal.instructions_hash,
        )?;
    }
    Ok(invalidated)
}
#[cfg(test)]
fn proposal_value(
    state_transaction: &StateTransaction<'_, '_>,
    multisig_account: &AccountId,
    instructions_hash: &HashOf<Vec<InstructionBox>>,
) -> Result<MultisigProposalValue, ValidationFail> {
    let proposal_state = proposal_state(state_transaction, multisig_account, instructions_hash)?;
    Ok(MultisigProposalValue::new(
        proposal_state.instructions,
        proposal_state.proposed_at_ms,
        proposal_state.expires_at_ms,
        proposal_state.approvals,
        proposal_state.is_relayed,
    ))
}
fn now_ms(state_transaction: &StateTransaction<'_, '_>) -> u64 {
    state_transaction
        ._curr_block
        .creation_time()
        .as_millis()
        .try_into()
        .expect("block creation time must fit into u64")
}
fn multisig_state_encode_error(err: norito::Error) -> ValidationFail {
    ValidationFail::InternalError(format!("failed to encode multisig state:\n{err}"))
}
fn multisig_state_decode_error(err: norito::Error) -> ValidationFail {
    ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
        "multisig state malformed:\n{err}"
    )))
}
fn map_find_error(err: FindError) -> ValidationFail {
    ValidationFail::InstructionFailed(InstructionExecutionError::Find(err))
}
fn map_validation_fail(err: ValidationFail) -> InstructionExecutionError {
    match err {
        ValidationFail::InstructionFailed(err) => err,
        ValidationFail::QueryFailed(QueryExecutionFail::Find(err)) => {
            InstructionExecutionError::Find(err)
        }
        ValidationFail::QueryFailed(QueryExecutionFail::Conversion(msg)) => {
            InstructionExecutionError::Conversion(msg)
        }
        ValidationFail::QueryFailed(err) => InstructionExecutionError::Query(err),
        ValidationFail::NotPermitted(msg) => {
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(msg))
        }
        other => InstructionExecutionError::InvariantViolation(other.to_string().into()),
    }
}
#[cfg(test)]
mod tests {
    mod cancellation;
    mod proposal_attempt;
    mod sccp_record;
    use super::*;
    use crate::{
        executor::Executor,
        kura::Kura,
        query::store::LiveQueryStore,
        sns::{
            SnsNamespace, get_name_record, policy_by_id, quote_resolved_name_registration,
            seed_default_namespace_policies_for_payment_asset,
        },
        state::{State, StateReadOnly, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::{
        IntoKeyValue, Registrable,
        account::{
            Account, AccountController, AccountId, MultisigMember, MultisigPolicy,
            rekey::{AccountAlias, AccountAliasDomain, AccountRekeyTransitionProvenance},
        },
        alias_setup::{
            AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasIntentV1,
            AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
        },
        asset::{AssetDefinition, AssetDefinitionId, AssetId},
        block::BlockHeader,
        isi::{
            AddSignatory, ExecuteTrigger, Grant, Mint, RemoveSignatory, SetAccountQuorum,
            SetKeyValue,
            alias_setup::EnsureAlias,
            settlement::{
                FxCorridorOracleEvidence, FxCorridorPricingContext, ResolvedSettlementMovement,
                ResolvedSettlementMovements, SettlementDetails, SettlementExecutionOrder,
                SettlementReceipt,
            },
        },
        kaigi::{KaigiId, KaigiRecord, NewKaigi},
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, UniversalAccountId},
        oracle::{FeedConfigVersion, FeedEvent, FeedEventOutcome, FeedSuccess, ObservationValue},
        permission::Permission,
        prelude::{Domain, InstructionBox, Json, Quantity, Register},
        transaction::{Executable, IvmBytecode},
    };
    use iroha_executor_data_model::isi::multisig::{
        DEFAULT_MULTISIG_TTL_MS, MultisigApprove, MultisigCancel, MultisigPropose,
        MultisigRegister, MultisigSpec,
    };
    use iroha_executor_data_model::permission::account::{
        AccountAliasPermissionScope, CanManageAccountAlias, CanRegisterAccount,
    };
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::{DataSpaceId, LaneId};
    use mv::storage::StorageReadOnly;
    use nonzero_ext::nonzero;
    use std::{
        collections::{BTreeMap, BTreeSet},
        num::{NonZeroU16, NonZeroU64},
    };
    fn new_account_id(key_pair: &KeyPair) -> AccountId {
        AccountId::new(key_pair.public_key().clone())
    }
    fn checked_keypair() -> KeyPair {
        KeyPair::try_random().expect("multisig ISI fixture key generation should succeed")
    }
    include!("multisig/core_execution_tests.rs");
    fn runtime_state(
        world: World,
        chain_id: ChainId,
        nexus: Option<iroha_config::parameters::actual::Nexus>,
    ) -> State {
        let mut config = TestChainConfig::new(world, 0);
        config.chain_id = chain_id;
        config.nexus = nexus;
        runtime_state_from_config(config)
    }
    fn runtime_state_from_config(config: TestChainConfig) -> State {
        use crate::sumeragi::startup;

        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        let consensus_mode = config.consensus_mode;
        let prepared =
            CertifiedTestChain::prepare(config).expect("prepare signed multisig genesis");
        let state = std::sync::Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished multisig State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &genesis_account,
            consensus_mode.into(),
            None,
        )
        .expect("apply original signed multisig genesis");
        state
    }
    fn runtime_header(state: &State, creation_time_ms: u64) -> BlockHeader {
        BlockHeader::new(
            nonzero!(2_u64),
            Some(
                state
                    .view()
                    .latest_block_hash()
                    .expect("original genesis parent"),
            ),
            None,
            creation_time_ms,
            0,
        )
    }
    macro_rules! runtime_tx {
        ($state:ident, $block:ident, $transaction:ident, $world:expr, $chain_id:expr) => {
            runtime_tx!($state, $block, $transaction, $world, $chain_id, 0);
        };
        ($state:ident, $block:ident, $transaction:ident, $world:expr, $chain_id:expr, $creation_time_ms:expr) => {
            let $state = runtime_state($world, ChainId::from($chain_id), None);
            let mut $block = $state.block(runtime_header(&$state, $creation_time_ms));
            let mut $transaction = $block.transaction_for_callback_testing();
        };
    }
    #[test]
    fn multisig_runtime_fixture_retains_original_chain_and_genesis_parent() {
        let chain_id = ChainId::from("multisig-runtime-original-source");
        let state = runtime_state(World::new(), chain_id.clone(), None);
        assert_eq!(state.chain_id_ref(), &chain_id);
        assert_eq!(state.view().height(), 1);
        let original = state.view().latest_block_hash().expect("signed genesis");
        let header = runtime_header(&state, 1_000);
        assert_eq!(header.height().get(), 2);
        assert_eq!(header.prev_block_hash(), Some(original));
        assert_eq!(header.creation_time_ms, 1_000);
    }
    macro_rules! tx {
        ($state:ident, $block:ident, $transaction:ident, $world:expr, $chain_id:expr) => {
            tx!($state, $block, $transaction, $world, $chain_id, 1_u64, 0);
        };
        ($state:ident, $block:ident, $transaction:ident, $world:expr, $chain_id:expr, $height:expr, $creation_time_ms:expr) => {
            let $state = State::new_with_chain(
                $world,
                Kura::blank_kura_for_testing(),
                LiveQueryStore::start_test(),
                ChainId::from($chain_id),
            );
            let mut $block = $state.block(BlockHeader::new(
                nonzero!($height),
                None,
                None,
                $creation_time_ms,
                0,
            ));
            let mut $transaction = $block.transaction();
        };
    }
    macro_rules! domain {
        ($transaction:ident, $owner:ident, $domain:ident, $message:expr) => {
            register_domain_with_name_lease(&mut $transaction, &$owner, &$domain, $message);
        };
    }
    macro_rules! account {
        ($transaction:ident, $authority:ident, $domain:ident, $account:ident, $message:expr) => {
            register_account_in_domain(
                &mut $transaction,
                &$authority,
                &$domain,
                &$account,
                $message,
            );
        };
    }
    macro_rules! msig {
        ($transaction:ident, $authority:ident, $domain:ident, $spec:ident, $message:expr) => {
            register_multisig_account(&mut $transaction, &$authority, &$domain, &$spec, $message)
        };
    }
    include!("multisig/parliament_rekey_tests.rs");
    fn spec(signatories: BTreeMap<AccountId, u8>, quorum: u16) -> MultisigSpec {
        MultisigSpec {
            signatories,
            quorum: NonZeroU16::new(quorum).unwrap(),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
        }
    }
    struct FiRegistrationAliasFixture {
        config: TestChainConfig,
        signer1: KeyPair,
        signer2: KeyPair,
        retail_account: AccountId,
        sbp: DataSpaceId,
        sbp_lane: LaneId,
        hbl_domain: DomainId,
        payment_asset_definition_id: AssetDefinitionId,
    }
    fn fi_registration_alias_fixture() -> FiRegistrationAliasFixture {
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let retail_account = new_account_id(&checked_keypair());
        let sbp = DataSpaceId::new(10);
        let sbp_lane = LaneId::new(1);
        let hbl_domain = DomainId::try_new("hbl", "sbp").expect("hbl.sbp domain");
        let payment_asset_definition_id: AssetDefinitionId = "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
            .parse()
            .expect("payment asset definition id");
        let mut world = World::with(
            [Domain::new(hbl_domain.clone()).build(&signer1_id)],
            [
                Account::new(signer1_id.clone()).build(&signer1_id),
                Account::new(signer2_id.clone()).build(&signer1_id),
            ],
            [AssetDefinition::numeric(
                payment_asset_definition_id.clone(),
                "xor".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&signer1_id)],
        );
        seed_default_namespace_policies_for_payment_asset(
            &mut world,
            &payment_asset_definition_id.to_string(),
        );
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: sbp,
                alias: "sbp".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("sbp dataspace catalog");
        nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
        // Retain SBP's configured physical lane geometry in the original fixture;
        // global topology and parameter control retain the universal lane.
        nexus.lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: sbp_lane,
                    dataspace_id: sbp,
                    alias: "sbp".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("SBP and universal lane catalog");
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.fees.fee_asset_id = payment_asset_definition_id.to_string();
        // The executor resolves aliases from committed SNS state. A static node
        // catalog and domain entity cannot replace either original parent lease.
        let bootstrap_dataspace = EnsureAlias::new(
            AliasIntentV1::Dataspace(iroha_data_model::alias_setup::AliasDataSpaceIntentV1 {
                dataspace: iroha_data_model::alias_setup::ResolvedDataSpaceV1::new(
                    "sbp".parse().expect("canonical sbp dataspace name"),
                    sbp,
                ),
                owner: signer1_id.clone(),
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: 1,
                expected_payment_asset: payment_asset_definition_id.clone(),
                max_amount: Quantity::zero(),
                valid_until_ms: u64::MAX,
            },
        );
        let bootstrap_domain = EnsureAlias::new(
            AliasIntentV1::Domain(iroha_data_model::alias_setup::AliasDomainIntentV1 {
                domain: iroha_data_model::alias_setup::ResolvedDomainV1::new(
                    hbl_domain.clone(),
                    sbp,
                ),
                owner: signer1_id.clone(),
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: 1,
                expected_payment_asset: payment_asset_definition_id.clone(),
                max_amount: Quantity::zero(),
                valid_until_ms: u64::MAX,
            },
        );
        let mut config = TestChainConfig::new(world, 0);
        config.chain_id = ChainId::from("multisig-fi-registration-alias-batch");
        config.nexus = Some(nexus);
        let genesis_account = AccountId::new(config.genesis_key.public_key().clone());
        // Foundational permissions belong to the actual genesis authority. The
        // original signed EnsureAlias batch retains its single global route;
        // SBP-scoped Grant instructions would require their own physical route.
        config.world.account_permissions_mut_for_testing().insert(
            genesis_account,
            BTreeSet::from([
                Permission::from(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Dataspace(sbp),
                }),
                Permission::from(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(hbl_domain.clone()),
                }),
            ]),
        );
        config.genesis_instructions = vec![bootstrap_dataspace.into(), bootstrap_domain.into()];
        FiRegistrationAliasFixture {
            config,
            signer1,
            signer2,
            retail_account,
            sbp,
            sbp_lane,
            hbl_domain,
            payment_asset_definition_id,
        }
    }
    #[test]
    fn multisig_fi_bootstrap_requires_each_exact_genesis_signer_permission() {
        for missing_domain_permission in [false, true] {
            let mut fixture = fi_registration_alias_fixture();
            let genesis_account = AccountId::new(fixture.config.genesis_key.public_key().clone());
            let permission = Permission::from(CanManageAccountAlias {
                scope: if missing_domain_permission {
                    AccountAliasPermissionScope::Domain(fixture.hbl_domain)
                } else {
                    AccountAliasPermissionScope::Dataspace(fixture.sbp)
                },
            });
            let permissions = fixture
                .config
                .world
                .account_permissions_mut_for_testing()
                .view()
                .get(&genesis_account)
                .expect("actual genesis signer permissions")
                .iter()
                .filter(|existing| *existing != &permission)
                .cloned()
                .collect();
            fixture
                .config
                .world
                .account_permissions_mut_for_testing()
                .insert(genesis_account.clone(), permissions);
            let failure = CertifiedTestChain::prepare(fixture.config)
                .expect_err("each exact parent permission is required by original signed genesis");
            assert_eq!(failure.state.view().height(), 0);
            assert!(matches!(
                &failure.error,
                crate::sumeragi::test_chain::TestChainError::OriginalGenesisExecution(_)
            ));
            assert!(
                format!("{:?}", failure.error).contains("alias.setup.authority_forbidden"),
                "missing exact permission must refuse at alias authority: {:?}",
                failure.error,
            );
            assert!(
                !failure
                    .state
                    .view()
                    .world()
                    .account_permissions()
                    .get(&genesis_account)
                    .expect("unapplied signer permissions")
                    .contains(&permission),
                "bootstrap cannot recreate an absent signer permission",
            );
        }
    }
    fn assert_multisig_executes_fi_registration_alias_batch(include_registration_uaid: bool) {
        let FiRegistrationAliasFixture {
            config,
            signer1,
            signer2,
            retail_account,
            sbp,
            sbp_lane,
            hbl_domain,
            payment_asset_definition_id,
        } = fi_registration_alias_fixture();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let state = runtime_state_from_config(config);
        assert_eq!(
            state
                .nexus_snapshot()
                .dataspace_catalog
                .by_alias("sbp")
                .map(|entry| entry.id),
            Some(sbp),
            "signed genesis retains the configured SBP catalog",
        );
        assert_eq!(
            state
                .nexus_snapshot()
                .lane_catalog
                .lanes()
                .iter()
                .map(|lane| (lane.id, lane.dataspace_id))
                .collect::<Vec<_>>(),
            vec![(LaneId::SINGLE, DataSpaceId::UNIVERSAL), (sbp_lane, sbp)],
            "signed genesis retains both original physical execution lanes",
        );
        assert_eq!(
            state
                .view()
                .world()
                .dataspace_catalog()
                .by_alias("sbp")
                .map(|entry| entry.id),
            Some(sbp),
            "the authoritative World view retains the same SBP mapping",
        );
        let block_header = runtime_header(&state, 0);
        let mut block = state.block(block_header);
        let proposal_call = Hash::prehashed([0xD3; Hash::LENGTH]);
        let approval_call = Hash::prehashed([0xD4; Hash::LENGTH]);
        block.admit_fastpq_source_for_testing(proposal_call);
        block.admit_fastpq_source_for_testing(approval_call);
        let mut tx = block.transaction_for_callback_testing();
        assert_eq!(
            crate::sns::resolve_active_dataspace_id_by_alias(
                tx.world(),
                tx.world().dataspace_catalog(),
                "sbp",
                tx.block_unix_timestamp_ms(),
            )
            .expect("original signed genesis retains the sbp name lease"),
            sbp,
        );
        assert_eq!(
            get_name_record(
                tx.world(),
                SnsNamespace::Dataspace,
                "sbp",
                tx.block_unix_timestamp_ms(),
            )
            .expect("committed bootstrap dataspace lease")
            .owner,
            signer1_id,
        );
        assert_eq!(
            get_name_record(
                tx.world(),
                SnsNamespace::Domain,
                &hbl_domain.to_string(),
                tx.block_unix_timestamp_ms(),
            )
            .expect("committed bootstrap FI domain lease")
            .owner,
            signer1_id,
        );
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        execute_register(
            &mut tx,
            &signer1_id,
            MultisigRegister::with_account(
                new_account_id(&checked_keypair()),
                hbl_domain.clone(),
                spec.clone(),
            ),
        )
        .expect("register multisig");
        let multisig_id =
            AccountId::new_multisig(multisig_policy_from_spec(&spec).expect("policy"));
        tx.world.add_account_permission(
            &multisig_id,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(sbp),
            }),
        );
        tx.world.add_account_permission(
            &multisig_id,
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(hbl_domain.clone()),
            }),
        );
        tx.world.add_account_permission(
            &multisig_id,
            Permission::from(CanRegisterAccount {
                domain: hbl_domain.clone(),
            }),
        );
        Mint::asset_quantity(
            1_000_u64,
            AssetId::of(payment_asset_definition_id.clone(), multisig_id.clone()),
        )
        .execute(&signer1_id, &mut tx)
        .expect("mint payment balance");
        let alias = AccountAlias::new(
            "clear-orbit-3941".parse().expect("label"),
            Some(AccountAliasDomain::new("hbl".parse().expect("domain"))),
            sbp,
        );
        let registration_uaid = include_registration_uaid.then(|| {
            UniversalAccountId::from_hash(Hash::new(
                b"retail_registration|alias=clear-orbit-3941@hbl.sbp",
            ))
        });
        let registration_account = if let Some(uaid) = registration_uaid {
            Account::new(retail_account.clone()).with_uaid(Some(uaid))
        } else {
            Account::new(retail_account.clone())
        };
        let resolved_alias = ResolvedAccountAliasV1::new(
            "clear-orbit-3941@hbl.sbp"
                .parse()
                .expect("resolved FI account alias"),
            sbp,
        );
        let selector = crate::alias_setup::selector_for_resolved_alias_target(
            &iroha_data_model::alias_setup::AliasTargetV1::AccountAlias(resolved_alias.clone()),
        )
        .expect("FI account alias selector");
        let quote = quote_resolved_name_registration(
            tx.world(),
            selector,
            &retail_account,
            1,
            None,
            tx.block_unix_timestamp_ms(),
        )
        .expect("FI account alias quote");
        let policy_version =
            policy_by_id(tx.world(), iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID)
                .expect("valid account alias policy state")
                .expect("account alias policy")
                .policy_version;
        let instructions = vec![
            InstructionBox::from(Register::account(registration_account)),
            InstructionBox::from(EnsureAlias::new(
                AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                    alias: resolved_alias,
                    target_account: retail_account.clone(),
                    provision: AccountProvisionV1::Existing,
                    role: AccountAliasRoleV1::Additional,
                }),
                AliasLeaseAcquisitionV1::new(1, None),
                AliasQuoteGuardV1 {
                    expected_policy_version: policy_version,
                    expected_payment_asset: payment_asset_definition_id.clone(),
                    max_amount: quote.charge_amount,
                    valid_until_ms: u64::MAX,
                },
            )),
        ];
        let instructions_hash = HashOf::new(&instructions);
        tx.tx_call_hash = Some(proposal_call);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("signer1 proposes FI registration batch");
        tx.tx_call_hash = Some(approval_call);
        execute_approve(
            &mut tx,
            &signer2_id,
            &MultisigApprove::new(multisig_id.clone(), instructions_hash),
        )
        .expect("signer2 approval executes FI registration batch");
        let lease = get_name_record(
            tx.world(),
            SnsNamespace::AccountAlias,
            "clear-orbit-3941@hbl.sbp",
            0,
        )
        .expect("FI alias lease should be active after multisig execution");
        assert_eq!(lease.owner, retail_account);
        assert_eq!(
            tx.world.account_aliases().get(&alias),
            Some(&retail_account),
            "FI alias binding should be visible after multisig execution"
        );
        if let Some(uaid) = registration_uaid {
            assert_eq!(
                tx.world.uaid_accounts.get(&uaid),
                Some(&retail_account),
                "UAID should be bound to the registered retail account"
            );
        }
    }

    #[test]
    fn register_existing_multisig_account_refreshes_ttl() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-register-refresh-ttl"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("acme", "universal").unwrap();
        let owner = checked_keypair();
        let owner_id = new_account_id(&owner);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer = checked_keypair();
        let signer_id = new_account_id(&signer);
        account!(tx, owner_id, domain_id, signer_id, "register signer");
        let spec = spec(BTreeMap::from([(signer_id.clone(), 1)]), 1);
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(
                new_account_id(&checked_keypair()),
                domain_id.clone(),
                spec.clone(),
            ),
        )
        .expect("initial register");
        let registered_multisig_id =
            AccountId::new_multisig(multisig_policy_from_spec(&spec).expect("policy"));
        let refreshed_ttl = NonZeroU64::new(86_400_000).unwrap();
        let refreshed_spec = MultisigSpec {
            transaction_ttl_ms: refreshed_ttl,
            ..spec
        };
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(
                registered_multisig_id.clone(),
                domain_id.clone(),
                refreshed_spec.clone(),
            ),
        )
        .expect("refresh existing multisig ttl");
        let stored_spec =
            multisig_spec(&tx, &registered_multisig_id).expect("refreshed spec must decode");
        assert_eq!(stored_spec.transaction_ttl_ms, refreshed_ttl);
        assert_eq!(stored_spec.signatories, refreshed_spec.signatories);
        assert_eq!(stored_spec.quorum, refreshed_spec.quorum);
    }
    #[test]
    fn register_materializes_missing_signatory_accounts() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-register-materialize"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("acme", "universal").unwrap();
        let owner = checked_keypair();
        let owner_id = new_account_id(&owner);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let missing_signer = checked_keypair();
        let missing_signer_id = new_account_id(&missing_signer);
        let spec = spec(
            BTreeMap::from([(owner_id.clone(), 1), (missing_signer_id.clone(), 1)]),
            2,
        );
        let multisig_seed = new_account_id(&checked_keypair());
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(multisig_seed, domain_id.clone(), spec.clone()),
        )
        .expect("register should materialize missing signatories");
        let created = tx
            .world
            .account(&missing_signer_id)
            .expect("missing signatory should be auto-created");
        assert!(
            created.metadata().get(&*MULTISIG_CREATED_VIA_KEY).is_some(),
            "auto-created signatory must carry multisig created_via marker"
        );
    }
    #[test]
    fn register_allows_non_owner_without_permission() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-register-authority-reject"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("acme", "universal").unwrap();
        let owner = checked_keypair();
        let owner_id = new_account_id(&owner);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let registrar = checked_keypair();
        let registrar_id = new_account_id(&registrar);
        account!(tx, owner_id, domain_id, registrar_id, "register registrar");
        let spec = spec(BTreeMap::from([(owner_id.clone(), 1)]), 1);
        let multisig_seed = new_account_id(&checked_keypair());
        execute_register(
            &mut tx,
            &registrar_id,
            MultisigRegister::with_account(multisig_seed, domain_id.clone(), spec),
        )
        .expect("registrar without permission should register multisig");
    }
    #[test]
    fn register_persists_multisig_metadata_on_authority_account() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-register-persists-metadata"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("acme", "universal").unwrap();
        let owner = checked_keypair();
        let owner_id = new_account_id(&owner);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer = checked_keypair();
        let signer_id = new_account_id(&signer);
        account!(tx, owner_id, domain_id, signer_id, "register signer");
        let spec = spec(BTreeMap::from([(signer_id.clone(), 1)]), 1);
        let multisig_seed = new_account_id(&checked_keypair());
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(multisig_seed, domain_id.clone(), spec.clone()),
        )
        .expect("register multisig");
        let registered_multisig_id = tx
            .world
            .accounts_iter()
            .find(|account| account.id().multisig_policy().is_some())
            .map(|account| account.id().clone())
            .expect("registered multisig account");
        let account = tx
            .world
            .account(&registered_multisig_id)
            .expect("multisig account present");
        let stored_spec = account
            .metadata()
            .get(&spec_key())
            .cloned()
            .expect("multisig/spec metadata");
        let stored_spec: MultisigSpec = stored_spec
            .try_into_any_norito()
            .expect("multisig/spec should decode");
        let stored_home_domain = account
            .metadata()
            .get(&home_domain_key())
            .cloned()
            .expect("multisig home-domain metadata");
        let stored_home_domain: Option<iroha_model_base::domain::DomainId> = stored_home_domain
            .try_into_any_norito()
            .expect("home-domain should decode");
        assert_eq!(
            stored_spec, spec,
            "registered authority must expose spec metadata"
        );
        assert_eq!(
            stored_home_domain,
            Some(domain_id),
            "registered authority must expose home-domain metadata"
        );
    }
    #[test]
    fn register_invalid_spec_does_not_materialize_missing_signatory() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-register-invalid-no-materialize"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("acme", "universal").unwrap();
        let owner = checked_keypair();
        let owner_id = new_account_id(&owner);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let missing_signer = checked_keypair();
        let missing_signer_id = new_account_id(&missing_signer);
        let invalid_spec = spec(
            BTreeMap::from([(owner_id.clone(), 1), (missing_signer_id.clone(), 1)]),
            3,
        );
        let multisig_seed = new_account_id(&checked_keypair());
        let err = execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(multisig_seed, domain_id.clone(), invalid_spec),
        )
        .expect_err("invalid quorum should reject registration");
        assert!(
            matches!(err, ValidationFail::NotPermitted(_)),
            "unexpected validation error for invalid quorum: {err:?}"
        );
        assert!(
            matches!(
                tx.world.account(&missing_signer_id),
                Err(FindError::Account(_))
            ),
            "failed registration must not materialize missing signatories"
        );
    }
    #[test]
    fn register_existing_account_does_not_materialize_missing_signatory() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-register-existing-account-no-materialize"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("acme", "universal").unwrap();
        let owner = checked_keypair();
        let owner_id = new_account_id(&owner);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let missing_signer = checked_keypair();
        let missing_signer_id = new_account_id(&missing_signer);
        let spec = spec(
            BTreeMap::from([(owner_id.clone(), 1), (missing_signer_id.clone(), 1)]),
            2,
        );
        let multisig_seed = new_account_id(&checked_keypair());
        account!(
            tx,
            owner_id,
            domain_id,
            multisig_seed,
            "pre-register multisig seed account"
        );
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(multisig_seed, domain_id.clone(), spec),
        )
        .expect_err("existing multisig seed account must reject register");
        assert!(
            matches!(
                tx.world.account(&missing_signer_id),
                Err(FindError::Account(_))
            ),
            "failed registration must not materialize missing signatories"
        );
    }
    #[test]
    fn add_signatory_updates_multisig_spec_and_roles() {
        tx!(state, block, tx, World::new(), "multisig-add-signatory");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        account!(tx, owner_id, domain_id, signer2_id, "register signer2");
        let spec = spec(BTreeMap::from([(signer1_id.clone(), 1)]), 1);
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        AddSignatory::new(multisig_id.clone(), signer2.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("add signatory");
        let mut updated_spec = spec.clone();
        updated_spec.signatories.insert(signer2_id.clone(), 1);
        let updated_policy = multisig_policy_from_spec(&updated_spec).expect("policy");
        let updated_account = AccountId::new_multisig(updated_policy);
        let updated = multisig_spec(&tx, &updated_account).expect("spec must decode after add");
        assert!(
            updated
                .signatories
                .keys()
                .any(|account| account.subject_id() == signer2_id.subject_id()),
            "added signatory must appear in spec"
        );
        assert!(
            matches!(tx.world.account(&multisig_id), Err(FindError::Account(_))),
            "multisig account should be rekeyed after add"
        );
        let multisig_role = multisig_role_for(Some(&domain_id), &updated_account);
        let signer_role = multisig_role_for(Some(&domain_id), &signer2_id);
        assert!(
            tx.world
                .account_roles_iter(&signer2_id)
                .any(|role| role == &multisig_role),
            "added signatory should gain multisig role"
        );
        assert!(
            tx.world
                .account_roles_iter(&updated_account)
                .any(|role| role == &signer_role),
            "multisig account should receive the signatory role"
        );
        let updated_account_data = tx
            .world
            .account(&updated_account)
            .expect("updated multisig account");
        let metadata_spec = updated_account_data
            .metadata()
            .get(&spec_key())
            .cloned()
            .expect("updated multisig/spec metadata");
        let metadata_spec: MultisigSpec = metadata_spec
            .try_into_any_norito()
            .expect("updated multisig/spec should decode");
        assert_eq!(
            metadata_spec, updated_spec,
            "rekeyed authority should keep metadata spec in sync"
        );
    }
    #[test]
    fn add_signatory_keeps_alias_record_and_pending_proposal_approvable() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-add-signatory-alias-continuity"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer3 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let signer3_id = new_account_id(&signer3);
        for signer_id in [&signer1_id, &signer2_id, &signer3_id] {
            register_account_in_domain(
                &mut tx,
                &owner_id,
                &domain_id,
                signer_id,
                "register signer",
            );
        }
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let alias = bind_account_label(&mut tx, &owner_id, &multisig_id, &domain_id, "cbdc");
        let instructions = Vec::<InstructionBox>::new();
        let instructions_hash = HashOf::new(&instructions);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("initial propose");
        AddSignatory::new(multisig_id.clone(), signer3.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("add signatory");
        let updated_spec = MultisigSpec {
            signatories: BTreeMap::from([
                (signer1_id.clone(), 1),
                (signer2_id.clone(), 1),
                (signer3_id.clone(), 1),
            ]),
            quorum: spec.quorum,
            transaction_ttl_ms: spec.transaction_ttl_ms,
        };
        let updated_account =
            AccountId::new_multisig(multisig_policy_from_spec(&updated_spec).expect("policy"));
        let rekey_record = tx
            .world
            .account_rekey_records
            .get(&alias)
            .expect("alias rekey record");
        assert_eq!(
            rekey_record.active_account_id, updated_account,
            "alias should resolve to the rekeyed multisig account"
        );
        assert_eq!(
            rekey_record.previous_account_ids,
            vec![multisig_id.clone()],
            "rekey record should retain the prior concrete multisig account"
        );
        assert_eq!(
            rekey_record.transition_provenance,
            vec![AccountRekeyTransitionProvenance::AccountIdRekey],
            "canonical multisig rekey must record trusted account-id provenance"
        );
        let lease = account_alias_lease_record(&tx, &alias);
        assert_eq!(
            lease.owner, updated_account,
            "authoritative SNS ownership must follow the canonical multisig account id"
        );
        let old_address = iroha_data_model::account::AccountAddress::from_account_id(&multisig_id)
            .expect("old multisig address");
        let new_address =
            iroha_data_model::account::AccountAddress::from_account_id(&updated_account)
                .expect("updated multisig address");
        assert!(
            lease
                .controllers
                .iter()
                .any(|controller| controller.account_address.as_ref() == Some(&new_address)),
            "SNS owner controller must follow the canonical multisig account id"
        );
        assert!(
            lease
                .controllers
                .iter()
                .all(|controller| controller.account_address.as_ref() != Some(&old_address)),
            "SNS controllers must not retain the obsolete multisig account id"
        );
        let proposal = proposal_value(&tx, &updated_account, &instructions_hash)
            .expect("proposal should move to the rekeyed account");
        assert_eq!(
            proposal.approvals,
            BTreeSet::from([signer1_id.clone()]),
            "existing approvals should survive add-signatory rekey"
        );
        let approval_entrypoint_hash = Hash::prehashed([0xd1; Hash::LENGTH]);
        tx.tx_call_hash = Some(approval_entrypoint_hash);
        execute_approve(
            &mut tx,
            &signer2_id,
            &MultisigApprove::new(updated_account.clone(), instructions_hash),
        )
        .expect("approval through rekeyed account");
        let outcome_key = multisig_approval_outcome_state_key(
            *approval_entrypoint_hash.as_ref(),
            &updated_account,
            &instructions_hash,
        );
        let outcome_bytes = tx
            .world
            .smart_contract_state
            .get(&outcome_key)
            .expect("rekeyed approval should leave an exact outcome");
        let outcome = norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(outcome_bytes)
            .expect("rekeyed approval outcome should decode");
        assert_eq!(outcome.entrypoint_account_id, updated_account);
        assert_eq!(outcome.resolved_multisig_account_id, updated_account);
        assert_eq!(outcome.status, MultisigApprovalOutcomeStatusV1::Executed);
        let terminal_execution_key = multisig_proposal_terminal_execution_state_key(
            *approval_entrypoint_hash.as_ref(),
            &updated_account,
            &instructions_hash,
        );
        let terminal_execution_bytes = tx
            .world
            .smart_contract_state
            .get(&terminal_execution_key)
            .expect("rekeyed finalization should use its signed lookup account");
        let terminal_execution = norito::decode_from_bytes::<
            MultisigProposalTerminalExecutionStateV1,
        >(terminal_execution_bytes)
        .expect("rekeyed terminal execution should decode");
        assert_eq!(terminal_execution.entrypoint_account_id, updated_account);
        assert_eq!(
            terminal_execution.terminal.multisig_account_id,
            updated_account
        );
        match proposal_value(&tx, &updated_account, &instructions_hash) {
            Ok(proposal) => {
                assert!(
                    matches!(proposal.is_relayed, Some(true)),
                    "executed proposal should be marked relayed when not pruned immediately"
                );
            }
            Err(ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::MetadataKey(
                _,
            ))))
            | Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound)) => {}
            Err(err) => panic!("unexpected proposal state after approval: {err:?}"),
        }
    }
    #[test]
    fn add_signatory_materializes_missing_account() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-add-signatory-materialize"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        let spec = spec(BTreeMap::from([(signer1_id.clone(), 1)]), 1);
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let missing_signer = checked_keypair();
        let missing_signer_id = new_account_id(&missing_signer);
        assert!(
            matches!(
                tx.world.account(&missing_signer_id),
                Err(FindError::Account(_))
            ),
            "precondition: signatory account must be missing"
        );
        AddSignatory::new(multisig_id.clone(), missing_signer.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("add signatory should materialize missing account");
        let created = tx
            .world
            .account(&missing_signer_id)
            .expect("missing signatory should be materialized");
        assert!(
            created.metadata().get(&*MULTISIG_CREATED_VIA_KEY).is_some(),
            "materialized account should be tagged as multisig-created"
        );
    }
    #[test]
    fn remove_signatory_updates_multisig_spec_and_revokes_roles() {
        tx!(state, block, tx, World::new(), "multisig-remove-signatory");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        account!(tx, owner_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        configure_roles(&mut tx, &owner_id, Some(&domain_id), &multisig_id, &spec)
            .expect("configure roles");
        RemoveSignatory::new(multisig_id.clone(), signer2.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("remove signatory");
        let updated_spec = MultisigSpec {
            signatories: BTreeMap::from([(signer1_id.clone(), 1)]),
            quorum: NonZeroU16::new(1).unwrap(),
            transaction_ttl_ms: spec.transaction_ttl_ms,
        };
        let updated_policy = multisig_policy_from_spec(&updated_spec).expect("policy");
        let updated_account = AccountId::new_multisig(updated_policy);
        let updated = multisig_spec(&tx, &updated_account).expect("spec must decode after remove");
        assert!(
            !updated
                .signatories
                .keys()
                .any(|account| account.subject_id() == signer2_id.subject_id()),
            "removed signatory must be absent from spec"
        );
        assert!(
            matches!(tx.world.account(&multisig_id), Err(FindError::Account(_))),
            "multisig account should be rekeyed after removal"
        );
        let multisig_role = multisig_role_for(Some(&domain_id), &updated_account);
        let signer_role = multisig_role_for(Some(&domain_id), &signer2_id);
        assert!(
            !tx.world
                .account_roles_iter(&signer2_id)
                .any(|role| role == &multisig_role),
            "removed signatory should lose multisig role"
        );
        assert!(
            !tx.world
                .account_roles_iter(&updated_account)
                .any(|role| role == &signer_role),
            "multisig account should drop removed signatory role"
        );
    }
    #[test]
    fn remove_signatory_keeps_alias_record_and_pending_proposal_approvable() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-remove-signatory-alias-continuity"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer3 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let signer3_id = new_account_id(&signer3);
        for signer_id in [&signer1_id, &signer2_id, &signer3_id] {
            register_account_in_domain(
                &mut tx,
                &owner_id,
                &domain_id,
                signer_id,
                "register signer",
            );
        }
        let spec = spec(
            BTreeMap::from([
                (signer1_id.clone(), 1),
                (signer2_id.clone(), 1),
                (signer3_id.clone(), 1),
            ]),
            2,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let alias = bind_account_label(&mut tx, &owner_id, &multisig_id, &domain_id, "cbdc");
        let instructions = Vec::<InstructionBox>::new();
        let instructions_hash = HashOf::new(&instructions);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("initial propose");
        RemoveSignatory::new(multisig_id.clone(), signer3.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("remove signatory");
        let updated_spec = MultisigSpec {
            signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            quorum: spec.quorum,
            transaction_ttl_ms: spec.transaction_ttl_ms,
        };
        let updated_account =
            AccountId::new_multisig(multisig_policy_from_spec(&updated_spec).expect("policy"));
        let rekey_record = tx
            .world
            .account_rekey_records
            .get(&alias)
            .expect("alias rekey record");
        assert_eq!(
            rekey_record.active_account_id, updated_account,
            "alias should resolve to the rekeyed multisig account"
        );
        assert_eq!(
            rekey_record.previous_account_ids,
            vec![multisig_id.clone()],
            "rekey record should retain the prior concrete multisig account"
        );
        let proposal = proposal_value(&tx, &updated_account, &instructions_hash)
            .expect("proposal should move to the rekeyed account");
        assert_eq!(
            proposal.approvals,
            BTreeSet::from([signer1_id.clone()]),
            "existing approvals should survive remove-signatory rekey"
        );
        execute_approve(
            &mut tx,
            &signer2_id,
            &MultisigApprove::new(updated_account.clone(), instructions_hash),
        )
        .expect("approval through rekeyed account");
        match proposal_value(&tx, &updated_account, &instructions_hash) {
            Ok(proposal) => {
                assert!(
                    matches!(proposal.is_relayed, Some(true)),
                    "executed proposal should be marked relayed when not pruned immediately"
                );
            }
            Err(ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::MetadataKey(
                _,
            ))))
            | Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound)) => {}
            Err(err) => panic!("unexpected proposal state after approval: {err:?}"),
        }
    }
    #[test]
    fn set_account_quorum_updates_multisig_spec() {
        tx!(state, block, tx, World::new(), "multisig-set-quorum");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        account!(tx, owner_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            1,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let new_quorum = NonZeroU16::new(2).unwrap();
        SetAccountQuorum::new(multisig_id.clone(), new_quorum)
            .execute(&owner_id, &mut tx)
            .expect("set quorum");
        let updated_spec = MultisigSpec {
            signatories: spec.signatories.clone(),
            quorum: new_quorum,
            transaction_ttl_ms: spec.transaction_ttl_ms,
        };
        let updated_policy = multisig_policy_from_spec(&updated_spec).expect("policy");
        let updated_account = AccountId::new_multisig(updated_policy);
        let updated =
            multisig_spec(&tx, &updated_account).expect("spec must decode after set quorum");
        assert_eq!(updated.quorum, new_quorum, "quorum update should persist");
        assert!(
            matches!(tx.world.account(&multisig_id), Err(FindError::Account(_))),
            "multisig account should be rekeyed after quorum update"
        );
    }
    #[test]
    fn add_signatory_rekeys_global_data_trigger_provenance_and_live_capability() {
        use crate::smartcontracts::triggers::set::SetReadOnly;
        use iroha_data_model::{
            events::data::DataEventFilter,
            prelude::{Action, Repeats, TriggerId},
            transaction::Executable,
            trigger::Trigger,
        };

        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-global-trigger-rekey",
            2_u64,
            0
        );
        let domain_id = DomainId::try_new("trigger-rekey", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        account!(tx, owner_id, domain_id, signer2_id, "register signer2");
        let spec = spec(BTreeMap::from([(signer1_id, 1)]), 1);
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let old_permission: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: multisig_id.clone(),
            }
            .into();
        Grant::account_permission(old_permission.clone(), multisig_id.clone())
            .execute(&owner_id, &mut tx)
            .expect("grant exact global-trigger capability");
        let trigger_id: TriggerId = "global_trigger_rekey".parse().expect("valid trigger id");
        Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Instructions(Vec::<InstructionBox>::new().into()),
                Repeats::Indefinitely,
                multisig_id.clone(),
                DataEventFilter::Any,
            )
            .expect("valid global data-trigger action"),
        ))
        .execute(&multisig_id, &mut tx)
        .expect("register capability-backed global data trigger");

        AddSignatory::new(multisig_id.clone(), signer2.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("rekey multisig account");
        let mut updated_spec = spec.clone();
        updated_spec.signatories.insert(signer2_id, 1);
        let updated_account =
            AccountId::new_multisig(multisig_policy_from_spec(&updated_spec).expect("policy"));
        let action = tx
            .world
            .triggers
            .data_triggers()
            .get(&trigger_id)
            .cloned()
            .expect("global trigger remains registered");
        assert_eq!(action.authority, updated_account);
        assert_eq!(
            crate::smartcontracts::isi::triggers::data_trigger_global_permission_grantee(
                &action.metadata
            )
            .expect("canonical global provenance"),
            Some(updated_account.clone())
        );
        let migrated_permission: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: updated_account.clone(),
            }
            .into();
        assert!(
            tx.world
                .account_permissions
                .get(&updated_account)
                .is_some_and(|permissions| permissions.contains(&migrated_permission))
        );
        assert!(
            tx.world
                .account_permissions
                .iter()
                .all(|(_, permissions)| !permissions.contains(&old_permission)),
            "the retired concrete account target must not retain a stale capability"
        );
        assert!(
            crate::smartcontracts::isi::triggers::isi::data_trigger_scope_is_currently_authorized(
                &tx, &action,
            ),
            "the migrated trigger and exact direct capability must remain coherent"
        );
    }

    #[test]
    fn add_signatory_does_not_resurrect_revoked_global_data_trigger_capability() {
        use crate::smartcontracts::triggers::set::SetReadOnly;
        use iroha_data_model::{
            events::data::DataEventFilter,
            prelude::{Action, Repeats, TriggerId},
            transaction::Executable,
            trigger::Trigger,
        };

        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-revoked-global-trigger-rekey",
            2_u64,
            0
        );
        let domain_id = DomainId::try_new("trigger-rekey-revoked", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        account!(tx, owner_id, domain_id, signer2_id, "register signer2");
        let spec = spec(BTreeMap::from([(signer1_id, 1)]), 1);
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let old_permission: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: multisig_id.clone(),
            }
            .into();
        Grant::account_permission(old_permission.clone(), multisig_id.clone())
            .execute(&owner_id, &mut tx)
            .expect("grant exact global-trigger capability");
        let trigger_id: TriggerId = "revoked_global_trigger_rekey"
            .parse()
            .expect("valid trigger id");
        Register::trigger(Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Instructions(Vec::<InstructionBox>::new().into()),
                Repeats::Indefinitely,
                multisig_id.clone(),
                DataEventFilter::Any,
            )
            .expect("valid global data-trigger action"),
        ))
        .execute(&multisig_id, &mut tx)
        .expect("register capability-backed global data trigger");
        assert!(
            tx.world
                .remove_account_permission(&multisig_id, &old_permission),
            "fixture revocation must remove the live direct capability"
        );

        AddSignatory::new(multisig_id.clone(), signer2.public_key().clone())
            .execute(&owner_id, &mut tx)
            .expect("rekey multisig account");
        let mut updated_spec = spec.clone();
        updated_spec.signatories.insert(signer2_id, 1);
        let updated_account =
            AccountId::new_multisig(multisig_policy_from_spec(&updated_spec).expect("policy"));
        let migrated_permission: Permission =
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: updated_account.clone(),
            }
            .into();
        assert!(
            tx.world
                .account_permissions
                .get(&updated_account)
                .is_none_or(|permissions| !permissions.contains(&migrated_permission)),
            "rekey must not resurrect a capability revoked after trigger registration"
        );
        let action = tx
            .world
            .triggers
            .data_triggers()
            .get(&trigger_id)
            .cloned()
            .expect("global trigger remains registered");
        assert_eq!(action.authority, updated_account);
        assert_eq!(
            crate::smartcontracts::isi::triggers::data_trigger_global_permission_grantee(
                &action.metadata
            )
            .expect("canonical global provenance"),
            Some(updated_account)
        );
        assert!(
            !crate::smartcontracts::isi::triggers::isi::data_trigger_scope_is_currently_authorized(
                &tx, &action,
            ),
            "the migrated provenance must stay unauthorized without a live direct capability"
        );
    }

    #[test]
    fn set_account_quorum_keeps_alias_record_and_pending_proposal_approvable() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-set-quorum-alias-continuity"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&owner_id, &mut tx)
            .expect("domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer3 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let signer3_id = new_account_id(&signer3);
        for signer_id in [&signer1_id, &signer2_id, &signer3_id] {
            register_account_in_domain(
                &mut tx,
                &owner_id,
                &domain_id,
                signer_id,
                "register signer",
            );
        }
        let spec = spec(
            BTreeMap::from([
                (signer1_id.clone(), 1),
                (signer2_id.clone(), 1),
                (signer3_id.clone(), 1),
            ]),
            3,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let alias = bind_account_label(&mut tx, &owner_id, &multisig_id, &domain_id, "cbdc");
        let instructions = Vec::<InstructionBox>::new();
        let instructions_hash = HashOf::new(&instructions);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("initial propose");
        let new_quorum = NonZeroU16::new(2).unwrap();
        SetAccountQuorum::new(multisig_id.clone(), new_quorum)
            .execute(&owner_id, &mut tx)
            .expect("set quorum");
        let updated_spec = MultisigSpec {
            signatories: spec.signatories.clone(),
            quorum: new_quorum,
            transaction_ttl_ms: spec.transaction_ttl_ms,
        };
        let updated_account =
            AccountId::new_multisig(multisig_policy_from_spec(&updated_spec).expect("policy"));
        let rekey_record = tx
            .world
            .account_rekey_records
            .get(&alias)
            .expect("alias rekey record");
        assert_eq!(
            rekey_record.active_account_id, updated_account,
            "alias should resolve to the rekeyed multisig account"
        );
        assert_eq!(
            rekey_record.previous_account_ids,
            vec![multisig_id.clone()],
            "rekey record should retain the prior concrete multisig account"
        );
        let proposal = proposal_value(&tx, &updated_account, &instructions_hash)
            .expect("proposal should move to the rekeyed account");
        assert_eq!(
            proposal.approvals,
            BTreeSet::from([signer1_id.clone()]),
            "existing approvals should survive quorum-change rekey"
        );
        execute_approve(
            &mut tx,
            &signer2_id,
            &MultisigApprove::new(updated_account.clone(), instructions_hash),
        )
        .expect("approval through rekeyed account");
        match proposal_value(&tx, &updated_account, &instructions_hash) {
            Ok(proposal) => {
                assert!(
                    matches!(proposal.is_relayed, Some(true)),
                    "executed proposal should be marked relayed when not pruned immediately"
                );
            }
            Err(ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::MetadataKey(
                _,
            ))))
            | Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound)) => {}
            Err(err) => panic!("unexpected proposal state after approval: {err:?}"),
        }
    }
    #[test]
    fn aliasless_rekey_rejects_active_kaigi_host_without_partial_mutation() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-aliasless-rekey-kaigi-continuity"
        );
        let domain_id = DomainId::try_new("rekey", "universal").expect("domain id");
        let old_account = new_account_id(&checked_keypair());
        let new_account = new_account_id(&checked_keypair());
        domain!(tx, old_account, domain_id, "register rekey domain");
        account!(
            tx,
            old_account,
            domain_id,
            old_account,
            "register old account"
        );
        let call_id = KaigiId::new(domain_id.clone(), "active-call".parse().expect("call name"));
        let record = KaigiRecord::from_new(
            &NewKaigi::with_defaults(call_id.clone(), old_account.clone()),
            0,
        );
        crate::smartcontracts::isi::kaigi::store_kaigi_record_for_testing(&mut tx, &record)
            .expect("store indexed Kaigi fixture");

        let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("aliasless rekey must not strand the active Kaigi host ID");
        assert!(
            error
                .to_string()
                .contains("rekey without durable account-alias continuity"),
            "unexpected error: {error}"
        );
        assert!(
            tx.world.account(&old_account).is_ok(),
            "rejected rekey must preserve the old account"
        );
        assert!(
            matches!(
                tx.world.account(&new_account),
                Err(FindError::Account(account)) if account == new_account
            ),
            "rejected rekey must not create the replacement account"
        );
    }
    #[test]
    fn account_rekey_rejects_historical_contract_subject_without_partial_mutation() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-contract-subject-rekey"
        );
        let deployer = new_account_id(&checked_keypair());
        let contract = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &deployer,
            91,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let old_account = contract.subject_id();
        let new_account = new_account_id(&checked_keypair());
        tx.world
            .bind_inactive_contract_subject_for_testing(contract.clone(), old_account.clone());
        let binding_before = tx
            .world
            .contract_subject_bindings
            .get(&contract)
            .cloned()
            .expect("retained contract binding");

        let error = rekey_account_id(&mut tx, &old_account, &new_account, None)
            .expect_err("historical contract subject must never be rekeyed");
        assert!(
            error
                .to_string()
                .contains(&format!("retained subject of contract `{contract}`")),
            "error must identify the exact retained contract: {error}"
        );
        assert!(tx.world.account(&old_account).is_ok());
        assert!(tx.world.account(&new_account).is_err());
        assert_eq!(
            tx.world.contract_subject_bindings.get(&contract),
            Some(&binding_before),
            "rejected rekey must preserve the retained lifecycle binding"
        );
        assert_eq!(
            tx.world.contract_subject_addresses.get(&old_account),
            Some(&contract),
            "rejected rekey must preserve the reverse subject index"
        );
    }
    #[test]
    fn rekey_account_id_preflights_every_alias_lease_without_partial_mutation() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-rekey-alias-lease-preflight"
        );
        let domain_id = DomainId::try_new("rekey", "universal").expect("domain id");
        let old_account = new_account_id(&checked_keypair());
        let new_account = new_account_id(&checked_keypair());
        let foreign_owner = new_account_id(&checked_keypair());
        domain!(tx, old_account, domain_id, "register rekey domain");
        account!(
            tx,
            old_account,
            domain_id,
            old_account,
            "register old account"
        );
        let aliases = [
            "a_missing",
            "b_foreign",
            "c_inactive",
            "d_malformed",
            "e_duplicate",
        ]
        .map(|label| bind_account_label(&mut tx, &old_account, &old_account, &domain_id, label));
        let lease_keys = aliases.clone().map(|alias| {
            let selector =
                crate::sns::selector_for_account_alias(&alias, &tx.nexus.dataspace_catalog)
                    .expect("selector");
            crate::sns::record_storage_key(&selector)
        });
        let canonical_leases = lease_keys.clone().map(|key| {
            tx.world
                .smart_contract_state
                .get(&key)
                .expect("canonical lease")
                .clone()
        });
        tx.world.smart_contract_state.remove(lease_keys[0].clone());
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("missing lease must reject account rekey");
        assert!(
            err.to_string()
                .contains("missing or owned by another account"),
            "{err}"
        );
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        tx.world
            .smart_contract_state
            .insert(lease_keys[0].clone(), canonical_leases[0].clone());
        let mut foreign_lease = account_alias_lease_record(&tx, &aliases[1]);
        foreign_lease.owner = foreign_owner;
        tx.world.smart_contract_state.insert(
            lease_keys[1].clone(),
            norito::codec::Encode::encode(&foreign_lease),
        );
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("foreign-owned lease must reject account rekey");
        assert!(
            err.to_string().contains("owned by another account"),
            "{err}"
        );
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        tx.world
            .smart_contract_state
            .insert(lease_keys[1].clone(), canonical_leases[1].clone());
        let mut inactive_lease = account_alias_lease_record(&tx, &aliases[2]);
        inactive_lease.expires_at_ms = 0;
        tx.world.smart_contract_state.insert(
            lease_keys[2].clone(),
            norito::codec::Encode::encode(&inactive_lease),
        );
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("inactive lease must reject account rekey");
        assert!(err.to_string().contains("not active"), "{err}");
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        tx.world
            .smart_contract_state
            .insert(lease_keys[2].clone(), canonical_leases[2].clone());
        let mut malformed_lease = canonical_leases[3].clone();
        malformed_lease.push(0xFF);
        tx.world
            .smart_contract_state
            .insert(lease_keys[3].clone(), malformed_lease);
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("non-canonical lease bytes must reject account rekey");
        let error_text = err.to_string();
        assert!(
            error_text.contains("failed to decode SNS lease")
                || error_text.contains("failed to decode account-alias SNS record")
                || error_text.contains("trailing bytes"),
            "{err}"
        );
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        tx.world
            .smart_contract_state
            .insert(lease_keys[3].clone(), canonical_leases[3].clone());
        let mut duplicate_replacement_lease = account_alias_lease_record(&tx, &aliases[4]);
        let new_address = iroha_data_model::account::AccountAddress::from_account_id(&new_account)
            .expect("new account address");
        duplicate_replacement_lease.controllers.push(
            iroha_data_model::sns::NameControllerV1::account(&new_address),
        );
        tx.world.smart_contract_state.insert(
            lease_keys[4].clone(),
            norito::codec::Encode::encode(&duplicate_replacement_lease),
        );
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("pre-existing replacement controller must reject account rekey");
        assert!(
            err.to_string()
                .contains("already contains the replacement account controller"),
            "{err}"
        );
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        tx.world
            .smart_contract_state
            .insert(lease_keys[4].clone(), canonical_leases[4].clone());
        let canonical_rekey_record = tx
            .world
            .account_rekey_records
            .get(&aliases[0])
            .cloned()
            .expect("canonical continuity record");
        tx.world.remove_account_rekey_record(&aliases[0]);
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("missing continuity record must reject account rekey");
        assert!(
            err.to_string().contains("canonical continuity record"),
            "{err}"
        );
        tx.world
            .replace_account_rekey_record(canonical_rekey_record.clone());
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        let mut malformed_rekey_record = canonical_rekey_record.clone();
        malformed_rekey_record
            .transition_provenance
            .push(AccountRekeyTransitionProvenance::AccountIdRekey);
        tx.world
            .replace_account_rekey_record(malformed_rekey_record);
        let err = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("malformed continuity record must reject account rekey");
        assert!(
            err.to_string().contains("malformed account rekey history"),
            "{err}"
        );
        assert_account_rekey_not_applied(&tx, &old_account, &new_account, &aliases);
        tx.world
            .replace_account_rekey_record(canonical_rekey_record);
        rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect("canonical active leases should migrate atomically");
        for alias in &aliases {
            assert_eq!(tx.world.account_aliases.get(alias), Some(&new_account));
            let lease = account_alias_lease_record(&tx, alias);
            assert_eq!(lease.owner, new_account);
            let new_address =
                iroha_data_model::account::AccountAddress::from_account_id(&new_account)
                    .expect("new account address");
            assert!(
                lease
                    .controllers
                    .iter()
                    .any(|controller| controller.account_address.as_ref() == Some(&new_address))
            );
        }
    }
    #[test]
    fn rekey_account_id_migrates_acquired_unbound_and_binding_cleared_leases() {
        let state = State::new_with_chain(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            ChainId::from("multisig-rekey-unbound-alias-leases"),
        );
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 10, 0));
        let mut tx = block.transaction();
        let domain_id = DomainId::try_new("unbound", "universal").expect("domain id");
        let old_account = new_account_id(&checked_keypair());
        let new_account = new_account_id(&checked_keypair());
        domain!(tx, old_account, domain_id, "register domain");
        account!(tx, old_account, domain_id, old_account, "register account");
        let aliases = ["acquired_unbound", "binding_cleared"].map(|label| {
            let alias = AccountAlias::new(
                label.parse().expect("alias label"),
                Some(AccountAliasDomain::new(domain_id.name().clone())),
                DataSpaceId::UNIVERSAL,
            );
            let selector =
                crate::sns::selector_for_account_alias(&alias, &tx.nexus.dataspace_catalog)
                    .expect("selector");
            let address = iroha_data_model::account::AccountAddress::from_account_id(&old_account)
                .expect("old account address");
            let lease = iroha_data_model::sns::NameRecordV1::new(
                selector.clone(),
                old_account.clone(),
                vec![iroha_data_model::sns::NameControllerV1::account(&address)],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                Metadata::default(),
            );
            tx.world.smart_contract_state.insert(
                crate::sns::record_storage_key(&selector),
                norito::codec::Encode::encode(&lease),
            );
            alias
        });
        for alias in &aliases {
            assert!(tx.world.account_aliases.get(alias).is_none());
            assert!(tx.world.account_rekey_records.get(alias).is_none());
        }
        rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect("all owned leases should migrate even without bindings");
        assert!(tx.world.account(&old_account).is_err());
        assert!(tx.world.account(&new_account).is_ok());
        let new_address = iroha_data_model::account::AccountAddress::from_account_id(&new_account)
            .expect("new account address");
        for alias in &aliases {
            let lease = account_alias_lease_record(&tx, alias);
            assert_eq!(lease.owner, new_account);
            assert_eq!(
                lease.controllers,
                vec![iroha_data_model::sns::NameControllerV1::account(
                    &new_address
                )]
            );
            assert!(
                tx.world.account_aliases.get(alias).is_none(),
                "unbound leases must remain unbound"
            );
            assert!(
                tx.world.account_rekey_records.get(alias).is_none(),
                "unbound leases must not gain resolution records"
            );
        }
    }
    #[test]
    fn governance_lock_owner_rekey_keeps_expiry_index_exact() {
        use crate::state::{
            GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
        };
        let state = State::new_with_chain(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            ChainId::from("multisig-governance-lock-index-rekey"),
        );
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut tx = block.transaction();
        let old_account = new_account_id(&checked_keypair());
        let new_account = new_account_id(&checked_keypair());
        let referendum_id = "rekeyed-governance-lock".to_owned();
        let expiry_height = 42;
        let mut locks = GovernanceLocksForReferendum::default();
        locks.locks.insert(
            old_account.clone(),
            GovernanceLockRecord {
                owner: old_account.clone(),
                amount: Quantity::one(),
                slashed: Quantity::zero(),
                expiry_height,
                direction: 0,
                duration_blocks: 1,
                custody: GovernanceLockCustody {
                    escrowed: !tx.gov.min_bond_amount.is_zero(),
                    asset_definition_id: tx.gov.voting_asset_id.clone(),
                    bond_escrow_account: tx.gov.bond_escrow_account.clone(),
                    slash_receiver_account: tx.gov.slash_receiver_account.clone(),
                },
            },
        );
        tx.world.put_governance_locks(referendum_id.clone(), locks);
        replace_account_id_in_governance(&mut tx, &old_account, &new_account);
        let locks = tx
            .world
            .governance_locks
            .get(&referendum_id)
            .expect("rekeyed lock set");
        assert!(locks.locks.get(&old_account).is_none());
        assert_eq!(
            locks
                .locks
                .get(&new_account)
                .expect("rekeyed governance lock")
                .owner,
            new_account,
        );
        assert_eq!(
            tx.world.governance_lock_expiry_index.get(&expiry_height),
            Some(&BTreeSet::from([(referendum_id, new_account)])),
        );
    }
    #[test]
    fn rekey_account_id_updates_subject_domain_indexes() {
        tx!(state, block, tx, World::new(), "multisig-rekey-indexes");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("default", "universal").unwrap();
        let old_key = checked_keypair();
        let old_account = new_account_id(&old_key);
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&old_account, &mut tx)
            .expect("domain registration");
        account!(
            tx,
            old_account,
            domain_id,
            old_account,
            "register old account"
        );
        let new_key = checked_keypair();
        let new_account = new_account_id(&new_key);
        rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect("rekey should succeed");
        assert!(
            matches!(tx.world.account(&old_account), Err(FindError::Account(_))),
            "old canonical account should be removed after rekey"
        );
        assert!(
            tx.world.account(&new_account).is_ok(),
            "new canonical account should be present after rekey"
        );
        let _ = domain_id;
    }
    #[test]
    fn aliasless_rekey_removes_inbound_permissions_before_old_account_id_reuse() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-rekey-permission-lifecycle"
        );
        let domain_id = DomainId::try_new("rekey-permissions", "universal").expect("domain id");
        let old_account = new_account_id(&checked_keypair());
        let new_account = new_account_id(&checked_keypair());
        let direct_holder = new_account_id(&checked_keypair());
        let role_holder = new_account_id(&checked_keypair());
        domain!(tx, old_account, domain_id, "register rekey domain");
        for (account, label) in [
            (&old_account, "register old account"),
            (&direct_holder, "register direct holder"),
            (&role_holder, "register role holder"),
        ] {
            register_account_in_domain(&mut tx, &old_account, &domain_id, account, label);
        }
        let definition = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "cash".parse().expect("asset name"),
        );
        let scoped_permissions = [
            Permission::from(
                iroha_executor_data_model::permission::account::CanReplaceAccountController {
                    account: old_account.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability {
                    account: old_account.clone(),
                    asset_definition: definition.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit {
                    account: old_account.clone(),
                    asset_definition: definition,
                },
            ),
        ];
        let unrelated: Permission =
            iroha_executor_data_model::permission::parameter::CanSetParameters.into();
        for permission in &scoped_permissions {
            tx.world
                .add_account_permission(&direct_holder, permission.clone());
        }
        tx.world
            .add_account_permission(&direct_holder, unrelated.clone());
        let role_id: RoleId = "REKEY_INBOUND_PERMISSIONS".parse().expect("role id");
        let mut role =
            Role::new(role_id.clone(), role_holder.clone()).add_permission(unrelated.clone());
        for permission in &scoped_permissions {
            role = role.add_permission(permission.clone());
        }
        Register::role(role)
            .execute(&old_account, &mut tx)
            .expect("register inbound-permission role");

        rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect("aliasless account rekey");

        let direct = tx
            .world
            .account_permissions
            .get(&direct_holder)
            .expect("unrelated direct permission remains");
        assert!(direct.contains(&unrelated));
        assert!(
            scoped_permissions
                .iter()
                .all(|permission| !direct.contains(permission)),
            "rekey must remove every direct permission targeting the old account ID",
        );
        let role = tx.world.roles.get(&role_id).expect("role remains");
        assert!(
            role.permissions()
                .any(|permission| permission == &unrelated)
        );
        assert!(role.permission_epochs().contains_key(&unrelated));
        assert!(
            scoped_permissions.iter().all(|permission| {
                !role.permissions().any(|candidate| candidate == permission)
                    && !role.permission_epochs().contains_key(permission)
            }),
            "rekey must remove role permissions and epochs targeting the old account ID",
        );

        Register::account(Account::new(old_account.clone()))
            .execute(&new_account, &mut tx)
            .expect("aliasless predecessor ID may be registered as a fresh lifecycle");
        assert!(tx.world.account(&old_account).is_ok());
        assert!(
            tx.world
                .account_permissions
                .get(&direct_holder)
                .is_none_or(|permissions| scoped_permissions
                    .iter()
                    .all(|permission| !permissions.contains(permission))),
            "old-ID reuse must not reactivate stale delegated authority",
        );
    }
    #[test]
    fn rekey_rejects_immutable_settlement_authority_and_every_typed_participant() {
        // Every variant pins both its authority and exact historical accounts.
        // Atomic additionally exercises first, middle and final source positions.
        let recipient = new_account_id(&checked_keypair());
        let sponsor = new_account_id(&checked_keypair());
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("receipt", "universal").expect("domain"),
            "cash".parse().expect("name"),
        );
        let mut movements = (0..255)
            .map(|_| {
                let account = new_account_id(&checked_keypair());
                ResolvedSettlementMovement {
                    source: AssetId::with_scope(
                        definition.clone(),
                        account,
                        iroha_data_model::asset::AssetBalanceScope::Global,
                    ),
                    destination: AssetId::with_scope(
                        definition.clone(),
                        recipient.clone(),
                        iroha_data_model::asset::AssetBalanceScope::Global,
                    ),
                    quantity: Quantity::one(),
                    metadata: Metadata::default(),
                }
            })
            .collect::<Vec<_>>();
        movements.sort_by(|a, b| (&a.source, &a.destination).cmp(&(&b.source, &b.destination)));
        let event = FeedEvent {
            feed_id: "rate".parse().expect("feed"),
            feed_config_version: FeedConfigVersion(1),
            slot: 1,
            request_hash: Hash::new(b"immutable-fx-receipt"),
            outcome: FeedEventOutcome::Success(FeedSuccess {
                value: ObservationValue::new(1, 0),
                entries: Vec::new(),
            }),
        };
        let context = FxCorridorPricingContext {
            policy_id: "corridor".parse().expect("policy"),
            policy_revision: 1,
            oracle_evidence: FxCorridorOracleEvidence {
                feed_id: event.feed_id.clone(),
                feed_config_version: event.feed_config_version,
                slot: event.slot,
                request_hash: event.request_hash,
                event_hash: HashOf::new(&event),
            },
            oracle_recorded_at_ms: 1,
            oracle_rate: ObservationValue::new(1, 0),
        };
        let variants = [
            SettlementDetails::Dvp(iroha_data_model::isi::DvpSettlementDetails {
                delivery: movements[0].clone(),
                payment: movements[254].clone(),
                order: SettlementExecutionOrder::DeliveryThenPayment,
            }),
            SettlementDetails::Pvp(iroha_data_model::isi::PvpSettlementDetails {
                primary: movements[0].clone(),
                counter: movements[254].clone(),
                order: SettlementExecutionOrder::PaymentThenDelivery,
            }),
            SettlementDetails::FxCorridor(iroha_data_model::isi::FxCorridorSettlementDetails {
                source: movements[0].clone(),
                destination: movements[254].clone(),
                context,
            }),
            SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
                movements: ResolvedSettlementMovements::try_from(movements)
                    .expect("exact canonical vector"),
                intent_hash: Hash::new(b"immutable-complete-intent"),
            }),
        ];
        for details in variants {
            let mut accounts = vec![sponsor.clone(), recipient.clone()];
            accounts.extend(
                details
                    .movements()
                    .enumerate()
                    .filter(|(index, _)| [0, 1, 127, 254].contains(index))
                    .map(|(_, movement)| movement.source.account().clone()),
            );
            for old_account in accounts {
                let new_account = new_account_id(&checked_keypair());
                let state = State::new_with_chain(
                    World::new(),
                    Kura::blank_kura_for_testing(),
                    LiveQueryStore::start_test(),
                    ChainId::from("immutable-settlement-rekey"),
                );
                let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
                let mut tx = block.transaction();
                Register::account(Account::new(old_account.clone()))
                    .execute(&old_account, &mut tx)
                    .expect("register current identity");
                let settlement_id = "immutable_receipt".parse().expect("id");
                let receipt = SettlementReceipt {
                    authority: sponsor.clone(),
                    metadata: Metadata::default(),
                    block_height: 1,
                    block_hash: tx._curr_block.hash(),
                    executed_at_ms: 0,
                    details: details.clone(),
                };
                tx.world.settlement_receipts.insert(settlement_id, receipt);
                let receipts_before = norito::encode_canonical(
                    &tx.world
                        .settlement_receipts
                        .iter()
                        .map(|(id, receipt)| (id.clone(), receipt.clone()))
                        .collect::<Vec<_>>(),
                )
                .expect("receipt bytes");
                let account_before = tx
                    .world
                    .accounts
                    .get(&old_account)
                    .expect("account")
                    .clone();
                let events_before = tx
                    .world
                    .internal_event_buf
                    .iter()
                    .map(|event| norito::encode_canonical(event.as_ref()).expect("event bytes"))
                    .collect::<Vec<_>>();
                let error = rekey_account_id(&mut tx, &old_account, &new_account, None)
                    .expect_err("signed receipt history must not be rewritten");
                assert!(
                    error
                        .to_string()
                        .contains("immutable committed settlement receipt")
                );
                assert_eq!(tx.world.accounts.get(&old_account), Some(&account_before));
                assert!(tx.world.accounts.get(&new_account).is_none());
                assert_eq!(
                    norito::encode_canonical(
                        &tx.world
                            .settlement_receipts
                            .iter()
                            .map(|(id, receipt)| (id.clone(), receipt.clone()))
                            .collect::<Vec<_>>()
                    )
                    .expect("receipt bytes"),
                    receipts_before
                );
                assert_eq!(
                    tx.world
                        .internal_event_buf
                        .iter()
                        .map(|event| norito::encode_canonical(event.as_ref()).expect("event bytes"))
                        .collect::<Vec<_>>(),
                    events_before
                );
            }
        }
    }
    #[test]
    fn replace_account_controller_preserves_principal_custody_and_exact_reserves() {
        use iroha_data_model::asset::{Asset, AssetBalanceScope};
        use iroha_model_base::topology::LaneId;

        let old = new_account_id(&checked_keypair());
        let new_key = checked_keypair();
        let new = new_account_id(&new_key);
        let other = new_account_id(&checked_keypair());
        let occupied_key = checked_keypair();
        let occupied = new_account_id(&occupied_key);
        let world = World::with(
            [],
            [
                Account::new(old.clone()).build(&old),
                Account::new(other.clone()).build(&old),
                Account::new(occupied.clone()).build(&old),
            ],
            [],
        );
        tx!(state, block, tx, world, "controller-principal-custody");
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("rewards", "universal").unwrap(),
            "token".parse().unwrap(),
        );
        let global = AssetId::new(definition.clone(), old.clone());
        let scoped = AssetId::with_scope(
            definition.clone(),
            old.clone(),
            AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
        );
        let external = AssetId::new(definition, other.clone());
        for (asset, available, stake) in [
            (global.clone(), 7_u32, 3_u32),
            (scoped.clone(), 6, 2),
            (external.clone(), 12, 0),
        ] {
            if stake != 0 {
                tx.world
                    .public_lane_stake_reserves
                    .insert(asset.clone(), Quantity::from(stake));
            }
            let (_, value) =
                Asset::new(asset.clone(), Quantity::from(available + stake)).into_key_value();
            tx.world.assets.insert(asset.clone(), value);
            tx.world.track_asset_holder(&asset);
        }
        tx.world.public_lane_stake_custody.insert(
            (LaneId::new(6), old.clone()),
            (global.clone(), Quantity::from(3_u32)),
        );
        tx.world.public_lane_stake_custody.insert(
            (LaneId::new(7), other.clone()),
            (scoped.clone(), Quantity::from(2_u32)),
        );

        // The public entry point must retain its same-controller and occupied-ID
        // refusals before touching any monetary projection.
        let monetary_bytes = |tx: &StateTransaction<'_, '_>| {
            macro_rules! capture {
                ($field:ident) => {
                    norito::encode_canonical(
                        &tx.world
                            .$field
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
                };
            }
            [
                capture!(public_lane_stake_custody),
                capture!(public_lane_stake_reserves),
                capture!(assets),
            ]
        };
        let before = monetary_bytes(&tx);
        let same = replace_account_controller(
            &old,
            &mut tx,
            &old,
            AccountController::Single(old.expect_single_signatory().clone()),
        )
        .unwrap_err();
        assert!(matches!(
            same,
            InstructionExecutionError::InvalidParameter(_)
        ));
        assert_eq!(monetary_bytes(&tx), before);
        let collision = replace_account_controller(
            &old,
            &mut tx,
            &old,
            AccountController::Single(occupied_key.public_key().clone()),
        )
        .unwrap_err();
        assert!(collision.to_string().contains("already exists"));
        assert_eq!(monetary_bytes(&tx), before);
        assert!(tx.world.accounts.get(&old).is_some());
        assert!(tx.world.accounts.get(&new).is_none());

        assert_eq!(
            replace_account_controller(
                &old,
                &mut tx,
                &old,
                AccountController::Single(new_key.public_key().clone())
            )
            .unwrap(),
            new
        );
        assert!(tx.world.accounts.get(&old).is_none());
        assert!(tx.world.accounts.get(&new).is_some());
        let new_global = replace_account_id_in_asset_id(&global, &old, &new);
        let new_scoped = replace_account_id_in_asset_id(&scoped, &old, &new);
        let expected_stake = BTreeMap::from([
            (new_global.clone(), Quantity::from(3_u32)),
            (new_scoped.clone(), Quantity::from(2_u32)),
        ]);
        assert!(
            tx.world
                .public_lane_stake_reserves
                .iter()
                .eq(expected_stake.iter())
        );
        assert_eq!(
            tx.world
                .public_lane_stake_custody
                .get(&(LaneId::new(6), new.clone())),
            Some(&(new_global.clone(), Quantity::from(3_u32)))
        );
        assert_eq!(
            tx.world
                .public_lane_stake_custody
                .get(&(LaneId::new(7), other)),
            Some(&(new_scoped.clone(), Quantity::from(2_u32)))
        );
        for (source, expected) in [(new_global, 10_u32), (new_scoped, 8), (external, 12)] {
            assert_eq!(
                tx.world.assets.get(&source).unwrap().as_ref(),
                &Quantity::from(expected)
            );
        }
        assert!(tx.world.assets.get(&global).is_none());
        assert!(tx.world.assets.get(&scoped).is_none());
    }
    #[test]
    fn rekey_public_lane_staking_custody_preserves_shared_asset_sums_and_scopes() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-rekey-stake-custody"
        );
        let old = new_account_id(&checked_keypair());
        let new = new_account_id(&checked_keypair());
        let other = new_account_id(&checked_keypair());
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("custody", "universal").unwrap(),
            "stake".parse().unwrap(),
        );
        let global = AssetId::new(definition.clone(), old.clone());
        let scoped = AssetId::with_scope(
            definition.clone(),
            old.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(
                iroha_model_base::topology::DataSpaceId::new(7),
            ),
        );
        let external = AssetId::new(definition, other.clone());
        for (lane, validator, asset, amount) in [
            (1, old.clone(), global.clone(), 3_u32),
            (2, other.clone(), global.clone(), 4_u32),
            (3, other.clone(), scoped.clone(), 5_u32),
            (4, old.clone(), external.clone(), 6_u32),
        ] {
            tx.world.public_lane_stake_custody.insert(
                (iroha_model_base::topology::LaneId::new(lane), validator),
                (asset, Quantity::from(amount)),
            );
        }
        for (asset, amount) in [
            (global.clone(), 7_u32),
            (scoped.clone(), 5),
            (external.clone(), 6),
        ] {
            tx.world
                .public_lane_stake_reserves
                .insert(asset, Quantity::from(amount));
        }
        replace_account_id_in_public_lane(&mut tx, &old, &new);
        let expected_reserves = BTreeMap::from([
            (
                replace_account_id_in_asset_id(&global, &old, &new),
                Quantity::from(7_u32),
            ),
            (
                replace_account_id_in_asset_id(&scoped, &old, &new),
                Quantity::from(5_u32),
            ),
            (external.clone(), Quantity::from(6_u32)),
        ]);
        assert!(
            tx.world
                .public_lane_stake_reserves
                .iter()
                .eq(expected_reserves.iter())
        );
        let mut actual_sums = BTreeMap::<AssetId, Quantity>::new();
        for ((_, validator), (asset, amount)) in tx.world.public_lane_stake_custody.iter() {
            assert_ne!(validator, &old);
            assert_ne!(asset.account(), &old);
            let sum = actual_sums
                .entry(asset.clone())
                .or_insert_with(Quantity::zero);
            *sum = sum.checked_add(amount).unwrap();
        }
        assert_eq!(actual_sums, expected_reserves);
        assert_eq!(
            tx.world
                .public_lane_stake_custody
                .get(&(iroha_model_base::topology::LaneId::new(4), new,)),
            Some(&(external, Quantity::from(6_u32)))
        );
    }

    #[test]
    fn rekey_public_lane_validators_ignores_mismatched_rows() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-rekey-public-lane-validators"
        );
        let old_key = checked_keypair();
        let old_account = new_account_id(&old_key);
        let new_key = checked_keypair();
        let new_account = new_account_id(&new_key);
        let valid_lane = iroha_model_base::topology::LaneId::new(8);
        let malformed_lane = iroha_model_base::topology::LaneId::new(9);
        let active = iroha_data_model::nexus::PublicLaneValidatorStatus::Active;
        let reward_asset_definition =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("multisig", "universal").expect("reward asset domain"),
                "reward".parse().expect("reward asset name"),
            );
        let old_reward_asset = iroha_data_model::asset::AssetId::new(
            reward_asset_definition.clone(),
            old_account.clone(),
        );
        tx.world.public_lane_validators.insert(
            (valid_lane, old_account.clone()),
            iroha_data_model::nexus::PublicLaneValidatorRecord {
                lane_id: valid_lane,
                validator: old_account.clone(),
                peer_id: iroha_model_base::peer::PeerId::from(
                    old_account.expect_single_signatory().clone(),
                ),
                stake_account: old_account.clone(),
                total_stake: iroha_primitives::numeric::Quantity::from(1_u32),
                self_stake: iroha_primitives::numeric::Quantity::from(1_u32),
                metadata: Metadata::default(),
                status: active.clone(),
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        tx.world.public_lane_validators.insert(
            (malformed_lane, new_account.clone()),
            iroha_data_model::nexus::PublicLaneValidatorRecord {
                lane_id: malformed_lane,
                validator: old_account.clone(),
                peer_id: iroha_model_base::peer::PeerId::from(
                    old_account.expect_single_signatory().clone(),
                ),
                stake_account: old_account.clone(),
                total_stake: iroha_primitives::numeric::Quantity::from(2_u32),
                self_stake: iroha_primitives::numeric::Quantity::from(2_u32),
                metadata: Metadata::default(),
                status: active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        tx.world.public_lane_stake_shares.insert(
            (valid_lane, old_account.clone(), old_account.clone()),
            iroha_data_model::nexus::PublicLaneStakeShare {
                lane_id: valid_lane,
                validator: old_account.clone(),
                staker: old_account.clone(),
                bonded: iroha_primitives::numeric::Quantity::from(3_u32),
                pending_unbonds: BTreeMap::new(),
                metadata: Metadata::default(),
            },
        );
        tx.world.public_lane_stake_shares.insert(
            (malformed_lane, old_account.clone(), old_account.clone()),
            iroha_data_model::nexus::PublicLaneStakeShare {
                lane_id: malformed_lane,
                validator: new_account.clone(),
                staker: old_account.clone(),
                bonded: iroha_primitives::numeric::Quantity::from(4_u32),
                pending_unbonds: BTreeMap::new(),
                metadata: Metadata::default(),
            },
        );
        tx.world.public_lane_stake_custody.insert(
            (valid_lane, old_account.clone()),
            (old_reward_asset.clone(), Quantity::from(3_u32)),
        );
        tx.world
            .public_lane_stake_reserves
            .insert(old_reward_asset.clone(), Quantity::from(3_u32));
        replace_account_id_in_public_lane(&mut tx, &old_account, &new_account);
        let new_custody_asset =
            replace_account_id_in_asset_id(&old_reward_asset, &old_account, &new_account);
        assert!(
            tx.world
                .public_lane_stake_custody
                .get(&(valid_lane, old_account.clone()))
                .is_none()
        );
        assert_eq!(
            tx.world
                .public_lane_stake_custody
                .get(&(valid_lane, new_account.clone())),
            Some(&(new_custody_asset.clone(), Quantity::from(3_u32)))
        );
        assert!(
            tx.world
                .public_lane_stake_reserves
                .get(&old_reward_asset)
                .is_none()
        );
        assert_eq!(
            tx.world.public_lane_stake_reserves.get(&new_custody_asset),
            Some(&Quantity::from(3_u32))
        );
        assert!(
            tx.world
                .public_lane_validators
                .get(&(valid_lane, old_account.clone()))
                .is_none(),
            "matching validator row should move away from the old key"
        );
        let moved = tx
            .world
            .public_lane_validators
            .get(&(valid_lane, new_account.clone()))
            .expect("matching validator row should move to the new key");
        assert_eq!(moved.validator, new_account);
        assert_eq!(moved.stake_account, new_account);
        let malformed = tx
            .world
            .public_lane_validators
            .get(&(malformed_lane, moved.validator.clone()))
            .expect("malformed row keyed by the new account should remain present");
        assert_eq!(
            malformed.validator, old_account,
            "mismatched row must not be repaired into a live matching validator"
        );
        assert_eq!(malformed.stake_account, old_account);
        assert!(
            tx.world
                .public_lane_stake_shares
                .get(&(valid_lane, old_account.clone(), old_account.clone()))
                .is_none(),
            "matching stake-share row should move away from the old key"
        );
        let moved_share = tx
            .world
            .public_lane_stake_shares
            .get(&(valid_lane, new_account.clone(), new_account.clone()))
            .expect("matching stake-share row should move to the new key");
        assert_eq!(moved_share.validator, new_account);
        assert_eq!(moved_share.staker, new_account);
        let malformed_share = tx
            .world
            .public_lane_stake_shares
            .get(&(malformed_lane, old_account.clone(), old_account.clone()))
            .expect("malformed stake-share row should remain on its old key");
        assert_eq!(
            malformed_share.validator, new_account,
            "mismatched stake-share validator must not be rewritten through key repair"
        );
        assert_eq!(malformed_share.staker, old_account);
        assert!(
            tx.world
                .public_lane_stake_shares
                .get(&(malformed_lane, new_account.clone(), new_account.clone()))
                .is_none(),
            "malformed stake-share row must not be moved into a live matching key"
        );
    }
    #[test]
    fn rekey_account_id_moves_asset_holder_index_to_new_account() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-rekey-asset-holder-index"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("default", "universal").unwrap();
        let old_key = checked_keypair();
        let old_account = new_account_id(&old_key);
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&old_account, &mut tx)
            .expect("domain registration");
        account!(
            tx,
            old_account,
            domain_id,
            old_account,
            "register old account"
        );
        let asset_def_id: iroha_data_model::asset::AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                domain_id.clone(),
                "rose".parse().unwrap(),
            );
        Register::asset_definition({
            let __asset_definition_id = asset_def_id.clone();
            iroha_data_model::asset::AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .execute(&old_account, &mut tx)
        .expect("register asset definition");
        let old_asset_id =
            iroha_data_model::asset::AssetId::new(asset_def_id.clone(), old_account.clone());
        Mint::asset_quantity(5_u32, old_asset_id.clone())
            .execute(&old_account, &mut tx)
            .expect("seed an actual nonzero balance and tracked supply");
        assert!(
            tx.world
                .asset_definition_nonzero_holders
                .get(&asset_def_id)
                .unwrap()
                .contains(&old_account)
        );
        let new_key = checked_keypair();
        let new_account = new_account_id(&new_key);
        rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect("rekey should succeed");
        let new_asset_id = iroha_data_model::asset::AssetId::with_scope(
            asset_def_id.clone(),
            new_account.clone(),
            *old_asset_id.scope(),
        );
        assert!(
            tx.world.assets.get(&old_asset_id).is_none(),
            "old account asset row should be removed"
        );
        assert!(
            tx.world.assets.get(&new_asset_id).is_some(),
            "new account asset row should exist"
        );
        let holders = tx
            .world
            .asset_definition_holders
            .get(&asset_def_id)
            .expect("holder index should exist after rekey");
        assert!(
            holders.contains(&new_account),
            "new account should be present in holder index"
        );
        assert!(
            !holders.contains(&old_account),
            "old account should be removed from holder index"
        );
        let nonzero = tx
            .world
            .asset_definition_nonzero_holders
            .get(&asset_def_id)
            .expect("migrated nonzero holder");
        assert!(nonzero.contains(&new_account));
        assert!(!nonzero.contains(&old_account));
        assert_eq!(nonzero.len(), 1);
        assert_eq!(
            tx.world
                .asset_definition(&asset_def_id)
                .unwrap()
                .total_quantity(),
            &Quantity::from(5_u32)
        );
    }

    #[test]
    fn rekey_moves_nonzero_membership_across_every_scope_and_ignores_zero_only_holdings() {
        use iroha_data_model::asset::{Asset, AssetBalancePolicy, AssetBalanceScope};
        for quantities in [[0_u32, 0_u32], [5, 0], [5, 7]] {
            tx!(
                state,
                block,
                tx,
                World::new(),
                "multisig-rekey-scoped-nonzero-index"
            );
            let domain = DomainId::try_new("rekey-scopes", "universal").unwrap();
            let old_account = new_account_id(&checked_keypair());
            domain!(tx, old_account, domain, "register rekey domain");
            account!(
                tx,
                old_account,
                domain,
                old_account,
                "register old scoped holder"
            );
            let definition =
                AssetDefinitionId::derive_from_components(domain.clone(), "units".parse().unwrap());
            Register::asset_definition(AssetDefinition::numeric(
                definition.clone(),
                "Scoped Units",
                AssetBalancePolicy::DataspaceRestricted,
                Some(domain.clone()),
            ))
            .execute(&old_account, &mut tx)
            .unwrap();
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let mut sources = Vec::new();
            for (index, amount) in quantities.into_iter().enumerate() {
                let id = AssetId::with_scope(
                    definition.clone(),
                    old_account.clone(),
                    AssetBalanceScope::Dataspace(DataSpaceId::new(7 + index as u64)),
                );
                if amount == 0 {
                    let (id, value) = Asset::new(id.clone(), Quantity::zero()).into_key_value();
                    tx.world.assets.insert(id.clone(), value);
                    tx.world.track_asset_holder(&id);
                } else {
                    Mint::asset_quantity(amount, id.clone())
                        .execute(&old_account, &mut tx)
                        .unwrap();
                }
                sources.push(id);
            }
            let total = Quantity::from(quantities.into_iter().sum::<u32>());
            let new_account = new_account_id(&checked_keypair());
            rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain)).unwrap();
            for (id, amount) in sources.iter().zip(quantities) {
                assert!(tx.world.assets.get(id).is_none());
                let moved =
                    AssetId::with_scope(definition.clone(), new_account.clone(), *id.scope());
                assert_eq!(
                    tx.world.assets.get(&moved).unwrap().as_ref(),
                    &Quantity::from(amount)
                );
                assert!(
                    tx.world
                        .asset_definition_assets
                        .get(&definition)
                        .unwrap()
                        .contains(&moved)
                );
            }
            assert!(tx.world.assets_by_account.get(&old_account).is_none());
            assert_eq!(
                tx.world.assets_by_account.get(&new_account).unwrap().len(),
                2
            );
            let nonzero = tx.world.asset_definition_nonzero_holders.get(&definition);
            assert!(!nonzero.is_some_and(|holders| holders.contains(&old_account)));
            assert_eq!(
                nonzero.is_some_and(|holders| holders.contains(&new_account)),
                !total.is_zero()
            );
            assert_eq!(
                tx.world
                    .asset_definition(&definition)
                    .unwrap()
                    .total_quantity(),
                &total
            );
        }
    }

    #[test]
    fn rekey_rejects_privacy_reserve_before_moving_account_or_asset() {
        use iroha_data_model::privacy::{
            PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyOrchardPoolBootstrapDigestV1,
            PrivacyPoolIdV1, PrivacyPoolNamespaceV1, PrivacyProtocolIdV1,
        };

        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-privacy-reserve-rekey"
        );
        let domain_id = DomainId::try_new("default", "universal").expect("domain ID");
        let old_account = new_account_id(&checked_keypair());
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&old_account, &mut tx)
            .expect("domain registration");
        account!(tx, old_account, domain_id, old_account, "reserve account");
        let definition_id = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "rose".parse().expect("asset name"),
        );
        Register::asset_definition(iroha_data_model::asset::AssetDefinition::numeric(
            definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&old_account, &mut tx)
        .expect("reserve definition");
        let old_asset_id =
            iroha_data_model::asset::AssetId::new(definition_id.clone(), old_account.clone());
        let (_, value) =
            iroha_data_model::asset::Asset::new(old_asset_id.clone(), Quantity::from(5_u32))
                .into_key_value();
        tx.world.assets.insert(old_asset_id.clone(), value);
        tx.world.track_asset_holder(&old_asset_id);
        let owner = crate::privacy_state::PrivacyPublicReserveOwnerV1::Orchard {
            namespace: PrivacyNamespaceV1::new(
                PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
                PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                    pool_id: PrivacyPoolIdV1::new([0xD7; 32]),
                }),
            ),
            bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1::new([0xD8; 32]),
        };
        let custody_key = crate::privacy_state::PrivacyCommitmentKeyV1::public_reserve_custody(
            owner.protocol_id(),
            &old_asset_id,
        )
        .expect("custody key");
        let custody_row = crate::privacy_state::PrivacyStateItemRecordV1::public_reserve_custody(
            old_asset_id.clone(),
            owner,
        )
        .expect("custody row");
        tx.world
            .privacy_commitments
            .insert(custody_key, custody_row.clone());
        let new_account = new_account_id(&checked_keypair());
        let new_asset_id =
            iroha_data_model::asset::AssetId::new(definition_id, new_account.clone());
        let error = rekey_account_id(&mut tx, &old_account, &new_account, Some(&domain_id))
            .expect_err("reserve account cannot be rekeyed while backing a pool");
        assert!(error.to_string().contains("reserve account"));
        assert!(tx.world.accounts.get(&old_account).is_some());
        assert!(tx.world.accounts.get(&new_account).is_none());
        assert_eq!(
            tx.world.assets.get(&old_asset_id).unwrap().as_ref(),
            &Quantity::from(5_u32)
        );
        assert!(tx.world.assets.get(&new_asset_id).is_none());
        assert_eq!(
            tx.world.privacy_commitments.get(&custody_key),
            Some(&custody_row)
        );
    }
    #[test]
    fn multisig_register_preserves_explicit_home_domain() {
        let source_domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("default", "universal").unwrap();
        let signer = new_account_id(&checked_keypair());
        let spec = spec(BTreeMap::from([(signer.clone(), 1)]), 1);
        let register = MultisigRegister::with_account(
            new_account_id(&checked_keypair()),
            source_domain.clone(),
            spec,
        );
        let signer_in_spec = register
            .spec
            .signatories
            .keys()
            .next()
            .expect("signatory exists");
        assert_eq!(register.home_domain.as_ref(), Some(&source_domain));
        assert_eq!(signer_in_spec.controller(), signer.controller());
    }
    #[test]
    fn multisig_register_uaid_rekeys_index_and_rejects_identity_changes_or_adoption() {
        use iroha_data_model::nexus::UniversalAccountId;
        tx!(state, block, tx, World::new(), "multisig-uaid-registration");
        let domain_id = DomainId::try_new("bsp", "cbsi").expect("domain");
        let owner = new_account_id(&checked_keypair());
        domain!(tx, owner, domain_id, "domain registration");
        account!(tx, owner, domain_id, owner, "owner registration");
        let signer = new_account_id(&checked_keypair());
        account!(tx, owner, domain_id, signer, "signer registration");
        let spec = spec(BTreeMap::from([(signer.clone(), 1)]), 1);
        let seed = new_account_id(&checked_keypair());
        let canonical = AccountId::new_multisig(multisig_policy_from_spec(&spec).unwrap());
        let uaid = UniversalAccountId::from_hash(Hash::new(b"native-multisig-uaid"));
        execute_register(
            &mut tx,
            &owner,
            MultisigRegister::with_account(seed.clone(), domain_id.clone(), spec.clone())
                .with_uaid(Some(uaid)),
        )
        .expect("fresh bound registration");
        assert!(tx.world.accounts.get(&seed).is_none());
        assert_eq!(tx.world.account(&canonical).unwrap().uaid(), Some(&uaid));
        assert_eq!(tx.world.uaid_accounts.get(&uaid), Some(&canonical));
        let before = load_multisig_account_state_optional(&tx, &canonical)
            .unwrap()
            .unwrap();
        execute_register(
            &mut tx,
            &owner,
            MultisigRegister::with_account(canonical.clone(), domain_id.clone(), spec.clone())
                .with_uaid(Some(uaid)),
        )
        .expect("same identity retry");
        for different in [
            None,
            Some(UniversalAccountId::from_hash(Hash::new(
                b"different-multisig-uaid",
            ))),
        ] {
            let error = execute_register(
                &mut tx,
                &owner,
                MultisigRegister::with_account(canonical.clone(), domain_id.clone(), spec.clone())
                    .with_uaid(different),
            )
            .expect_err("immutable identity mismatch");
            assert!(error.to_string().contains("immutable universal identity"));
            assert_eq!(tx.world.account(&canonical).unwrap().uaid(), Some(&uaid));
            assert_eq!(tx.world.uaid_accounts.get(&uaid), Some(&canonical));
            assert_eq!(
                load_multisig_account_state_optional(&tx, &canonical)
                    .unwrap()
                    .unwrap(),
                before
            );
        }
        let other_signer = new_account_id(&checked_keypair());
        account!(
            tx,
            owner,
            domain_id,
            other_signer,
            "other signer registration"
        );
        let mut other_spec = spec.clone();
        other_spec.signatories = BTreeMap::from([(other_signer, 1)]);
        let unbound = AccountId::new_multisig(multisig_policy_from_spec(&other_spec).unwrap());
        execute_register(
            &mut tx,
            &owner,
            MultisigRegister::with_account(unbound.clone(), domain_id.clone(), other_spec.clone()),
        )
        .expect("registration without UAID remains supported");
        let error = execute_register(
            &mut tx,
            &owner,
            MultisigRegister::with_account(unbound.clone(), domain_id.clone(), other_spec)
                .with_uaid(Some(UniversalAccountId::from_hash(Hash::new(
                    b"retroactive-multisig-uaid",
                )))),
        )
        .expect_err("cannot retrofit an existing immutable identity");
        assert!(error.to_string().contains("immutable universal identity"));
        assert_eq!(tx.world.account(&unbound).unwrap().uaid(), None);
        // Removing canonical native state does not make an already registered
        // account adoptable, even when its immutable identity exactly matches.
        tx.world
            .smart_contract_state
            .remove(multisig_account_state_key(&canonical));
        let error = execute_register(
            &mut tx,
            &owner,
            MultisigRegister::with_account(canonical.clone(), domain_id, spec)
                .with_uaid(Some(uaid)),
        )
        .expect_err("no native state adoption");
        assert!(
            error
                .to_string()
                .contains("without canonical native account state")
        );
        assert!(
            load_multisig_account_state_optional(&tx, &canonical)
                .unwrap()
                .is_none()
        );
        assert_eq!(tx.world.account(&canonical).unwrap().uaid(), Some(&uaid));
    }

    #[test]
    fn multisig_metadata_cannot_reconstruct_missing_native_account_state() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-native-state-required"
        );
        let domain_id = DomainId::try_new("bsp", "cbsi").expect("parse FI domain");
        let owner_id = new_account_id(&checked_keypair());
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer_id = new_account_id(&checked_keypair());
        account!(tx, owner_id, domain_id, signer_id, "register signer");
        let spec = spec(BTreeMap::from([(signer_id.clone(), 1)]), 1);
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(
                new_account_id(&checked_keypair()),
                domain_id.clone(),
                spec.clone(),
            ),
        )
        .expect("register multisig");
        let registered_multisig_id =
            AccountId::new_multisig(multisig_policy_from_spec(&spec).expect("policy"));
        tx.world
            .smart_contract_state
            .remove(multisig_account_state_key(&registered_multisig_id));
        let error = execute_propose(
            &mut tx,
            &signer_id,
            &MultisigPropose::new(registered_multisig_id.clone(), Vec::new(), None),
        )
        .expect_err("metadata alone must not materialize native multisig state");
        assert!(matches!(
            error,
            ValidationFail::QueryFailed(QueryExecutionFail::NotFound)
        ));
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_account_state_key(&registered_multisig_id))
                .is_none(),
            "rejected proposal must not recreate native account state",
        );
    }
    #[test]
    fn multisig_metadata_must_match_native_account_state() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-metadata-native-state-consistency"
        );
        let domain_id = DomainId::try_new("bsp", "cbsi").expect("parse FI domain");
        let owner_id = new_account_id(&checked_keypair());
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer_id = new_account_id(&checked_keypair());
        account!(tx, owner_id, domain_id, signer_id, "register signer");
        let spec = spec(BTreeMap::from([(signer_id.clone(), 1)]), 1);
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(
                new_account_id(&checked_keypair()),
                domain_id.clone(),
                spec.clone(),
            ),
        )
        .expect("register multisig");
        let registered_multisig_id =
            AccountId::new_multisig(multisig_policy_from_spec(&spec).expect("policy"));
        let mut divergent_spec = spec.clone();
        divergent_spec.transaction_ttl_ms = NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS + 1).unwrap();
        tx.world
            .accounts
            .get_mut(&registered_multisig_id)
            .expect("multisig account")
            .metadata
            .insert(spec_key(), Json::new(divergent_spec));
        let error = execute_propose(
            &mut tx,
            &signer_id,
            &MultisigPropose::new(registered_multisig_id.clone(), Vec::new(), None),
        )
        .expect_err("spec metadata disagreement must fail closed");
        assert!(matches!(
            error,
            ValidationFail::QueryFailed(QueryExecutionFail::Conversion(message))
                if message.contains("multisig/spec metadata disagrees")
        ));
        let account = tx
            .world
            .accounts
            .get_mut(&registered_multisig_id)
            .expect("multisig account");
        account.metadata.insert(spec_key(), Json::new(spec));
        account
            .metadata
            .insert(home_domain_key(), Json::new(None::<DomainId>));
        let error = execute_propose(
            &mut tx,
            &signer_id,
            &MultisigPropose::new(registered_multisig_id, Vec::new(), None),
        )
        .expect_err("home-domain metadata disagreement must fail closed");
        assert!(matches!(
            error,
            ValidationFail::QueryFailed(QueryExecutionFail::Conversion(message))
                if message.contains("home-domain metadata disagrees")
        ));
    }
    #[test]
    fn multisig_register_supports_domainless_home_domain() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-domainless-register"
        );
        let owner_id = new_account_id(&checked_keypair());
        Register::account(iroha_data_model::account::NewAccount::new(owner_id.clone()))
            .execute(&owner_id, &mut tx)
            .expect("register domainless owner");
        let signer = new_account_id(&checked_keypair());
        let spec = spec(BTreeMap::from([(signer.clone(), 1)]), 1);
        let multisig_seed = new_account_id(&checked_keypair());
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(
                multisig_seed,
                None::<iroha_model_base::domain::DomainId>,
                spec,
            ),
        )
        .expect("register domainless multisig");
        let registered_multisig_id = tx
            .world
            .accounts_iter()
            .find(|account| account.id().multisig_policy().is_some())
            .map(|account| account.id().clone())
            .expect("registered multisig account");
        assert_eq!(
            multisig_home_domain(&tx, &registered_multisig_id).expect("multisig home domain"),
            None,
            "domainless multisig should persist an empty home domain",
        );
        assert!(
            tx.world.account(&registered_multisig_id).is_ok(),
            "registered multisig should remain present"
        );
        assert!(
            tx.world.account(&signer).is_ok(),
            "materialized signatory should remain present"
        );
    }
    #[test]
    fn multisig_spec_uses_domainless_subject_identity() {
        let shared_key = checked_keypair().public_key().clone();
        let first = AccountId::new(shared_key.clone());
        let second = AccountId::new(shared_key);
        let spec = spec(BTreeMap::from([(first, 1), (second, 1)]), 1);
        assert_eq!(
            spec.signatories.len(),
            1,
            "domainless account ids must collapse identical subjects"
        );
    }
    #[test]
    fn set_account_quorum_rejects_unreachable_quorum() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-set-quorum-invalid"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("wonderland", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&owner_id, &mut tx)
            .expect("domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        account!(tx, owner_id, domain_id, signer1_id, "register signer1");
        account!(tx, owner_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            1,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let unreachable_quorum = NonZeroU16::new(3).unwrap();
        let err = SetAccountQuorum::new(multisig_id, unreachable_quorum)
            .execute(&owner_id, &mut tx)
            .expect_err("quorum above total weight should fail");
        assert!(
            matches!(
                err,
                InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                    _
                ))
            ),
            "unexpected error for unreachable quorum: {err:?}"
        );
    }
    #[test]
    fn multisig_propose_rejects_ttl_above_default() {
        runtime_tx!(state, block, tx, World::new(), "multisig-ttl-chain");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("ttl", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        domain!(tx, signer1_id, domain_id, "domain registration");
        account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
        account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_account_key = checked_keypair();
        let multisig_id = new_account_id(&multisig_account_key);
        let register =
            MultisigRegister::with_account(multisig_id.clone(), domain_id.clone(), spec.clone());
        Executor::Initial
            .execute_instruction(&mut tx, &signer1_id, InstructionBox::from(register))
            .expect("multisig register");
        let policy = multisig_policy_from_spec(&spec).expect("policy");
        let expected_id = AccountId::new_multisig(policy);
        let override_ttl =
            NonZeroU64::new(spec.transaction_ttl_ms.get().saturating_add(1)).unwrap();
        let propose = MultisigPropose::new(expected_id.clone(), Vec::new(), Some(override_ttl));
        let result = Executor::Initial.execute_instruction(
            &mut tx,
            &signer1_id,
            InstructionBox::from(propose),
        );
        match result {
            Err(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("ttl violates the restriction"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected TTL violation, got {other:?}"),
        }
    }
    #[test]
    fn multisig_signatory_can_propose_without_roles() {
        tx!(state, block, tx, World::new(), "multisig-signatory-propose");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("signatory", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        domain!(tx, signer1_id, domain_id, "domain registration");
        account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
        account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, signer1_id, domain_id, spec, "register multisig account");
        let instructions: Vec<InstructionBox> = Vec::new();
        let propose = MultisigPropose::new(multisig_id.clone(), instructions, None);
        execute_propose(&mut tx, &signer1_id, &propose).expect("signatory propose without roles");
    }
    #[test]
    fn multisig_propose_repairs_missing_state_from_controller() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("repairable", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let mut world = World::new();
        let selector = crate::sns::selector_for_domain(&domain_id).expect("selector");
        let address = iroha_data_model::account::AccountAddress::from_account_id(&signer1_id)
            .expect("signer address");
        let lease = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            signer1_id.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            crate::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&lease),
        );
        let state = State::new_with_chain(
            world,
            kura,
            query_handle,
            ChainId::from("multisig-repair-from-controller"),
        );
        let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(block_header);
        let mut tx = block.transaction();
        domain!(tx, signer1_id, domain_id, "domain registration");
        account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
        account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, signer1_id, domain_id, spec, "register multisig account");
        tx.world
            .smart_contract_state
            .remove(multisig_account_state_key(&multisig_id));
        tx.world
            .smart_contract_state
            .remove(multisig_signatory_index_key(&signer1_id));
        tx.world
            .smart_contract_state
            .remove(multisig_signatory_index_key(&signer2_id));
        let account = tx
            .world
            .accounts
            .get_mut(&multisig_id)
            .expect("registered multisig");
        account.metadata = Metadata::default();
        account.insert((*MULTISIG_CREATED_VIA_KEY).clone(), Json::new("implicit"));
        let instructions: Vec<InstructionBox> = Vec::new();
        let propose = MultisigPropose::new(multisig_id.clone(), instructions, None);
        let error = execute_propose(&mut tx, &signer1_id, &propose)
            .expect_err("controller data must not reconstruct missing authenticated state");
        assert!(matches!(
            error,
            ValidationFail::QueryFailed(QueryExecutionFail::NotFound)
        ));
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_account_state_key(&multisig_id))
                .is_none(),
            "failed reconstruction must leave native multisig state absent"
        );
        assert!(load_signatory_memberships(&tx, &signer1_id).is_empty());
        assert!(load_signatory_memberships(&tx, &signer2_id).is_empty());
    }
    #[test]
    fn multisig_register_indexes_signatory_memberships() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-signatory-index-register"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("signatory-index", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        domain!(tx, signer1_id, domain_id, "domain registration");
        account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
        account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_account_id =
            msig!(tx, signer1_id, domain_id, spec, "register multisig account");
        assert_eq!(
            load_signatory_memberships(&tx, &signer1_id),
            BTreeSet::from([multisig_account_id.clone()])
        );
        assert_eq!(
            load_signatory_memberships(&tx, &signer2_id),
            BTreeSet::from([multisig_account_id])
        );
    }
    #[test]
    fn multisig_rekey_repoints_signatory_memberships() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-signatory-index-rekey"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("signatory-rekey", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer3 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let signer3_id = new_account_id(&signer3);
        domain!(tx, signer1_id, domain_id, "domain registration");
        for (account_id, label) in [
            (&signer1_id, "register signer1"),
            (&signer2_id, "register signer2"),
            (&signer3_id, "register signer3"),
        ] {
            register_account_in_domain(&mut tx, &signer1_id, &domain_id, account_id, label);
        }
        let initial_spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let initial_multisig_account_id = msig!(
            tx,
            signer1_id,
            domain_id,
            initial_spec,
            "register multisig account"
        );
        AddSignatory {
            account: initial_multisig_account_id.clone(),
            signatory: signer3.public_key().clone(),
        }
        .execute(&signer1_id, &mut tx)
        .expect("add signatory");
        let updated_spec = spec(
            BTreeMap::from([
                (signer1_id.clone(), 1),
                (signer2_id.clone(), 1),
                (signer3_id.clone(), 1),
            ]),
            2,
        );
        let updated_multisig_account_id =
            AccountId::new_multisig(multisig_policy_from_spec(&updated_spec).expect("policy"));
        assert_ne!(initial_multisig_account_id, updated_multisig_account_id);
        assert_eq!(
            load_signatory_memberships(&tx, &signer1_id),
            BTreeSet::from([updated_multisig_account_id.clone()])
        );
        assert_eq!(
            load_signatory_memberships(&tx, &signer2_id),
            BTreeSet::from([updated_multisig_account_id.clone()])
        );
        assert_eq!(
            load_signatory_memberships(&tx, &signer3_id),
            BTreeSet::from([updated_multisig_account_id])
        );
    }
    #[test]
    fn multisig_approval_preserves_contract_call_trigger_metadata_for_non_default_entrypoints() {
        use iroha_data_model::{
            HasMetadata,
            events::execute_trigger::ExecuteTriggerEventFilter,
            isi::ExecuteTrigger,
            prelude::Json,
            transaction::Executable,
            trigger::{
                Trigger,
                action::{Action, Repeats},
            },
        };
        use iroha_model_base::metadata::Metadata;
        use iroha_model_base::name::Name;
        use kotodama_lang::compiler::Compiler as KotodamaCompiler;
        use kotodama_lang::compiler::{CompilerMode, CompilerOptions};
        runtime_tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-trigger-contract-entrypoint"
        );
        tx.tx_call_hash = Some(
            tx.direct_execution_identity()
                .expect("component approval root"),
        );
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let owner_keypair = checked_keypair();
        let owner_id = new_account_id(&owner_keypair);
        Register::account(iroha_data_model::account::NewAccount::new(owner_id.clone()))
            .execute(&owner_id, &mut tx)
            .expect("register owner");
        Register::account(iroha_data_model::account::NewAccount::new(
            signer1_id.clone(),
        ))
        .execute(&owner_id, &mut tx)
        .expect("register signer1");
        Register::account(iroha_data_model::account::NewAccount::new(
            signer2_id.clone(),
        ))
        .execute(&owner_id, &mut tx)
        .expect("register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = new_account_id(&checked_keypair());
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(
                multisig_id.clone(),
                None::<iroha_model_base::domain::DomainId>,
                spec.clone(),
            ),
        )
        .expect("register multisig account");
        let multisig_id = tx
            .world
            .accounts_iter()
            .find(|account| account.id().multisig_policy().is_some())
            .map(|account| account.id().clone())
            .expect("registered multisig account");
        Grant::account_permission(
            Permission::new("Admin".to_owned(), Json::new(())),
            multisig_id.clone(),
        )
        .execute(&owner_id, &mut tx)
        .expect("grant trigger entrypoint permission to the multisig authority");
        let (program, manifest) =
            KotodamaCompiler::new_with_options(CompilerOptions {
                mode: CompilerMode::Production,
                ..CompilerOptions::default()
            })
            .compile_source_with_manifest(
                r#"
seiyaku TriggerDispatch { permission Admin;
  kotoage fn main() authorize(Admin) {
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("entrypoint"), value: Json::parse("1"));
  }

  kotoage fn alternate() authorize(Admin) {
    ledger::account::set_metadata(account: context::authority(), key: Name::parse("entrypoint"), value: Json::parse("2"));
  }
}
"#,
            )
            .expect("compile trigger dispatch contract");
        let (bytecode, contract_address) =
            install_trigger_contract(&mut tx, &owner_id, &owner_keypair, program, manifest, 6_061);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &multisig_id,
                Grant::account_permission(
                    iroha_executor_data_model::permission::account::CanModifyAccountMetadata {
                        account: multisig_id.clone(),
                    },
                    contract_address.subject_id(),
                )
                .into(),
            )
            .expect(
                "multisig owner delegates its exact metadata permission to the contract subject",
            );
        let trigger_id: iroha_data_model::trigger::TriggerId = "contract_dispatch".parse().unwrap();
        let mut trigger_metadata = Metadata::default();
        trigger_metadata.insert(
            Name::from_str("contract_entrypoint").expect("static metadata key"),
            Json::new("alternate"),
        );
        trigger_metadata.insert(
            Name::from_str("contract_address").expect("static metadata key"),
            Json::new(contract_address.to_string()),
        );
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Ivm(bytecode),
                Repeats::Exactly(1),
                multisig_id.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(trigger_metadata),
        );
        let instructions = vec![
            InstructionBox::from(Register::trigger(trigger)),
            InstructionBox::from(ExecuteTrigger::new(trigger_id.clone())),
        ];
        let instructions_hash = HashOf::new(&instructions);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("signatory propose");
        let proposal = proposal_value(&tx, &multisig_id, &instructions_hash)
            .expect("proposal exists after propose");
        let register = proposal
            .instructions
            .first()
            .expect("proposal should register trigger")
            .as_any()
            .downcast_ref::<iroha_data_model::isi::RegisterBox>()
            .expect("first instruction must be register");
        let iroha_data_model::isi::RegisterBox::Trigger(register_trigger) = register else {
            panic!("first instruction must be register trigger");
        };
        let stored_entrypoint = register_trigger
            .object()
            .action()
            .metadata()
            .get("contract_entrypoint")
            .expect("stored trigger metadata should keep contract_entrypoint")
            .clone()
            .try_into_any_norito::<String>()
            .expect("entrypoint metadata should decode as string");
        assert_eq!(stored_entrypoint, "alternate");
        execute_approve(
            &mut tx,
            &signer2_id,
            &MultisigApprove::new(multisig_id.clone(), instructions_hash),
        )
        .expect("signatory approve should execute alternate entrypoint");
        let entrypoint_key: Name = "entrypoint".parse().expect("entrypoint metadata key");
        let executed_value = tx
            .world
            .account(&multisig_id)
            .expect("multisig account should exist")
            .metadata()
            .get(&entrypoint_key)
            .expect("alternate entrypoint should write account metadata")
            .clone()
            .try_into_any_norito::<norito::json::Value>()
            .expect("entrypoint account metadata should decode");
        assert_eq!(executed_value, norito::json!(2));
    }
    #[test]
    fn multisig_signatory_can_approve_without_roles() {
        tx!(state, block, tx, World::new(), "multisig-signatory-approve");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("signatory-approve", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        domain!(tx, signer1_id, domain_id, "domain registration");
        account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
        account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, signer1_id, domain_id, spec, "register multisig account");
        let instructions: Vec<InstructionBox> = Vec::new();
        let instructions_hash = HashOf::new(&instructions);
        let propose = MultisigPropose::new(multisig_id.clone(), instructions, None);
        execute_propose(&mut tx, &signer1_id, &propose).expect("signatory propose");
        let pending_entrypoint_hash = Hash::prehashed([0xa4; Hash::LENGTH]);
        tx.tx_call_hash = Some(pending_entrypoint_hash);
        let pending_approve = MultisigApprove::new(multisig_id.clone(), instructions_hash);
        execute_approve(&mut tx, &signer1_id, &pending_approve)
            .expect("duplicate subject approval should remain below quorum");
        let pending_outcome_key = multisig_approval_outcome_state_key(
            *pending_entrypoint_hash.as_ref(),
            &multisig_id,
            &instructions_hash,
        );
        let pending_outcome_bytes = tx
            .world
            .smart_contract_state
            .get(&pending_outcome_key)
            .expect("successful pre-quorum approval should leave an exact outcome");
        let pending_outcome =
            norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(pending_outcome_bytes)
                .expect("pre-quorum approval outcome should decode");
        assert_eq!(
            pending_outcome.status,
            MultisigApprovalOutcomeStatusV1::NotExecuted
        );
        assert_eq!(pending_outcome.entrypoint_account_id, multisig_id);
        assert_eq!(pending_outcome.resolved_multisig_account_id, multisig_id);
        let terminal_entrypoint_hash = Hash::prehashed([0xa5; Hash::LENGTH]);
        tx.tx_call_hash = Some(terminal_entrypoint_hash);
        let approve = MultisigApprove::new(multisig_id.clone(), instructions_hash);
        execute_approve(&mut tx, &signer2_id, &approve).expect("signatory approve without roles");
        let execution_key = multisig_proposal_terminal_execution_state_key(
            *terminal_entrypoint_hash.as_ref(),
            &multisig_id,
            &instructions_hash,
        );
        let execution_bytes = tx
            .world
            .smart_contract_state
            .get(&execution_key)
            .expect("finalized proposal should leave transaction-bound terminal state")
            .clone();
        let execution_state =
            norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(&execution_bytes)
                .expect("transaction-bound terminal state should decode");
        assert_eq!(execution_state.terminal_block_height, 1);
        assert_eq!(execution_state.entrypoint_account_id, multisig_id);
        assert_eq!(
            execution_state.terminal_entrypoint_hash,
            *terminal_entrypoint_hash.as_ref()
        );
        let executed_outcome_key = multisig_approval_outcome_state_key(
            *terminal_entrypoint_hash.as_ref(),
            &multisig_id,
            &instructions_hash,
        );
        let executed_outcome_bytes = tx
            .world
            .smart_contract_state
            .get(&executed_outcome_key)
            .expect("quorum approval should leave an exact executed outcome");
        let executed_outcome =
            norito::decode_from_bytes::<MultisigApprovalOutcomeV1>(executed_outcome_bytes)
                .expect("executed approval outcome should decode");
        assert_eq!(
            executed_outcome.status,
            MultisigApprovalOutcomeStatusV1::Executed
        );
        assert_eq!(executed_outcome.entrypoint_account_id, multisig_id);
        assert_eq!(executed_outcome.resolved_multisig_account_id, multisig_id);
        let mut conflicting_state = execution_state.terminal;
        conflicting_state.terminal_at_ms = conflicting_state.terminal_at_ms.saturating_add(1);
        let err = store_multisig_proposal_terminal_execution_state(
            &mut tx,
            &conflicting_state,
            &multisig_id,
        )
        .expect_err("transaction-bound terminal state must be append-only");
        assert!(
            matches!(err, ValidationFail::InternalError(message) if message.contains("conflicting immutable multisig terminal execution state"))
        );
        assert_eq!(
            tx.world.smart_contract_state.get(&execution_key),
            Some(&execution_bytes),
            "conflicting write must not alter transaction-bound terminal state"
        );
    }
    #[test]
    fn relayed_multisig_execution_leaves_only_transaction_bound_terminal_state() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-relayed-terminal-state"
        );
        let relay_account = new_account_id(&checked_keypair());
        let relay_instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "relay execution".to_owned(),
        ))];
        let relay_instructions_hash = HashOf::new(&relay_instructions);
        let relay_state = MultisigProposalState::new(
            relay_account.clone(),
            relay_instructions_hash,
            relay_instructions,
            1,
            u64::MAX,
            BTreeSet::from([relay_account.clone()]),
            Some(true),
        );
        let terminal_entrypoint_hash = Hash::prehashed([0xb7; Hash::LENGTH]);
        tx.tx_call_hash = Some(terminal_entrypoint_hash);
        maybe_store_relayed_proposal_execution_state(&mut tx, &relay_state, &relay_account)
            .expect("relayed execution should persist immutable evidence");
        let execution_key = multisig_proposal_terminal_execution_state_key(
            *terminal_entrypoint_hash.as_ref(),
            &relay_account,
            &relay_instructions_hash,
        );
        let execution_bytes = tx
            .world
            .smart_contract_state
            .get(&execution_key)
            .expect("relayed execution should leave transaction-bound terminal state");
        let execution_state =
            norito::decode_from_bytes::<MultisigProposalTerminalExecutionStateV1>(execution_bytes)
                .expect("relayed terminal execution state should decode");
        assert_eq!(
            execution_state.terminal.status,
            MultisigProposalTerminalStatus::Finalized
        );
        assert_eq!(execution_state.terminal.proposal.is_relayed, Some(true));
        assert_eq!(execution_state.entrypoint_account_id, relay_account);
        assert_eq!(execution_state.terminal_block_height, 1);
        assert_eq!(
            execution_state.terminal_entrypoint_hash,
            *terminal_entrypoint_hash.as_ref()
        );
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(
                    &relay_account,
                    &relay_instructions_hash,
                ))
                .is_none(),
            "relayed lifecycle state remains active and must not create the mutable terminal key"
        );
    }
    #[test]
    fn terminal_state_rekey_does_not_fabricate_transaction_bound_execution_evidence() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-terminal-rekey-evidence"
        );
        let old_account = new_account_id(&checked_keypair());
        let new_account = new_account_id(&checked_keypair());
        let instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "historical execution".to_owned(),
        ))];
        let instructions_hash = HashOf::new(&instructions);
        let terminal_state = MultisigProposalTerminalState::new(
            old_account.clone(),
            instructions_hash,
            MultisigProposalValue::new(
                instructions,
                1,
                u64::MAX,
                BTreeSet::from([old_account.clone()]),
                None,
            ),
            MultisigProposalTerminalStatus::Finalized,
            2,
        );
        store_multisig_proposal_terminal_state(&mut tx, &terminal_state)
            .expect("historical terminal state should store");
        let rekey_entrypoint_hash = Hash::prehashed([0xc9; Hash::LENGTH]);
        tx.tx_call_hash = Some(rekey_entrypoint_hash);
        move_multisig_proposals(&mut tx, &old_account, &new_account)
            .expect("rekey must preserve terminal history");
        let moved_bytes = tx
            .world
            .smart_contract_state
            .get(&multisig_proposal_terminal_state_key(
                &old_account,
                &instructions_hash,
            ))
            .expect("original terminal state must remain queryable");
        let moved_state = norito::decode_from_bytes::<MultisigProposalTerminalState>(moved_bytes)
            .expect("rekeyed terminal state should decode");
        assert_eq!(moved_state.multisig_account_id, old_account);
        assert_eq!(moved_state, terminal_state);
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(
                    &new_account,
                    &instructions_hash,
                ))
                .is_none(),
            "rekey must not rewrite terminal history under the new policy"
        );
        let mut changed_history = terminal_state;
        changed_history.terminal_at_ms += 1;
        assert!(
            store_multisig_proposal_terminal_state(&mut tx, &changed_history).is_err(),
            "terminal history must be immutable after rekey"
        );
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_execution_state_key(
                    *rekey_entrypoint_hash.as_ref(),
                    &new_account,
                    &instructions_hash,
                ))
                .is_none(),
            "rekeying historical lifecycle state must not create execution evidence"
        );
    }
    #[test]
    fn deliberate_policy_change_invalidation_terminalizes_every_other_proposal_before_rekey() {
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("recover", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let mut world = World::new();
        seed_domain_name_lease(&mut world, &owner_id, &domain_id);
        let state = runtime_state(
            world,
            ChainId::from("recovery-invalidates-multisig-proposals"),
            None,
        );
        let block_header = runtime_header(&state, 1_000);
        let mut block = state.block(block_header);
        let mut tx = block.transaction_for_callback_testing();
        domain!(tx, owner_id, domain_id, "domain registration");
        for (account_id, label) in [
            (&owner_id, "register owner"),
            (&signer1_id, "register signer1"),
            (&signer2_id, "register signer2"),
        ] {
            register_account_in_domain(&mut tx, &owner_id, &domain_id, account_id, label);
        }
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        bind_account_label(&mut tx, &owner_id, &multisig_id, &domain_id, "company");
        let active_instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "active before recovery".to_owned(),
        ))];
        let active_hash = HashOf::new(&active_instructions);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer1_id,
                InstructionBox::from(MultisigPropose::new(
                    multisig_id.clone(),
                    active_instructions,
                    None,
                )),
            )
            .expect("create active proposal");
        let expired_instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "expired before recovery".to_owned(),
        ))];
        let expired_hash = HashOf::new(&expired_instructions);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer1_id,
                InstructionBox::from(MultisigPropose::new(
                    multisig_id.clone(),
                    expired_instructions,
                    None,
                )),
            )
            .expect("create proposal to expire");
        let expired_state =
            proposal_state(&tx, &multisig_id, &expired_hash).expect("expired proposal state");
        store_multisig_proposal_state(
            &mut tx,
            &MultisigProposalState::new(
                expired_state.multisig_account_id,
                expired_state.instructions_hash,
                expired_state.instructions,
                expired_state.proposed_at_ms,
                1_000,
                expired_state.approvals,
                expired_state.is_relayed,
            ),
        )
        .expect("seed expired proposal timestamp");
        let replacement1 = checked_keypair();
        let replacement2 = checked_keypair();
        let replacement_policy =
            multisig_policy_for_members(&[(&replacement1, 1), (&replacement2, 1)]);
        let recovered_account = AccountId::new_multisig(replacement_policy.clone());
        let policy_change_instructions = vec![
            InstructionBox::from(MultisigInvalidateOutstanding::new(multisig_id.clone())),
            InstructionBox::from(iroha_data_model::isi::ReplaceAccountController {
                account: multisig_id.clone(),
                new_controller: AccountController::multisig(replacement_policy),
            }),
        ];
        let policy_change_hash = HashOf::new(&policy_change_instructions);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer1_id,
                InstructionBox::from(MultisigPropose::new(
                    multisig_id.clone(),
                    policy_change_instructions,
                    None,
                )),
            )
            .expect("propose deliberate invalidating policy change");
        let unauthorized = execute_invalidate_outstanding(
            &mut tx,
            &signer1_id,
            &MultisigInvalidateOutstanding::new(multisig_id.clone()),
        )
        .expect_err("a signatory cannot directly invalidate company proposals");
        assert!(matches!(unauthorized, ValidationFail::NotPermitted(_)));
        tx.tx_call_hash = Some(Hash::prehashed([0xd4; Hash::LENGTH]));
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer2_id,
                InstructionBox::from(MultisigApprove::new(
                    multisig_id.clone(),
                    policy_change_hash,
                )),
            )
            .expect("approve and execute deliberate invalidating policy change");
        assert!(tx.world.accounts.get(&recovered_account).is_some());
        for hash in [active_hash, expired_hash] {
            assert!(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_state_key(&recovered_account, &hash))
                    .is_none(),
                "rekey must not migrate an invalidated proposal"
            );
            assert!(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_terminal_state_key(&multisig_id, &hash,))
                    .is_some(),
                "rekey must preserve terminal evidence under its original controller"
            );
        }
        let terminal_status = |hash| {
            let bytes = tx
                .world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(&multisig_id, &hash))
                .expect("terminal policy-change evidence");
            norito::decode_from_bytes::<MultisigProposalTerminalState>(bytes)
                .expect("terminal policy-change evidence should decode")
                .status
        };
        assert_eq!(
            terminal_status(active_hash),
            MultisigProposalTerminalStatus::Canceled
        );
        assert_eq!(
            terminal_status(expired_hash),
            MultisigProposalTerminalStatus::Expired
        );
        assert_eq!(
            terminal_status(policy_change_hash),
            MultisigProposalTerminalStatus::Finalized,
            "the executing policy-change proposal must finalize rather than cancel itself"
        );
    }
    #[test]
    fn multisig_approve_executes_staged_mint_like_trigger_with_json_args() {
        use iroha_data_model::{
            events::execute_trigger::ExecuteTriggerEventFilter,
            transaction::Executable,
            trigger::{
                Trigger,
                action::{Action, Repeats},
            },
        };
        runtime_tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-staged-mint-json-args"
        );
        tx.tx_call_hash = Some(
            tx.direct_execution_identity()
                .expect("component approval root"),
        );
        let domain_id: DomainId = DomainId::try_new("staged", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        domain!(tx, signer1_id, domain_id, "domain registration");
        account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
        account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, signer1_id, domain_id, spec, "register multisig account");
        Grant::account_permission(
            Permission::new("staged_mint_request_run".into(), Json::new(())),
            multisig_id.clone(),
        )
        .execute(&signer1_id, &mut tx)
        .expect("grant staged mint permission");
        let src = format!(
            r#"
            seiyaku StagedMintRequest {{ permission staged_mint_request_run;
              // Runtime trigger authority: {multisig_id}
              error enum StagedMintError {{
                DuplicateRequest = 1,
                UnsupportedAction = 2,
                UnsupportedAssetDefinition = 3,
                DestinationAccountMismatch = 4,
                InvalidAmount = 5,
                MissingOrInvalidField = 6,
              }}

              state StateMap<Name, bytes> Requests_requested_by_actor;
              state StateMap<Name, AccountId> ToAccount;
              state StateMap<Name, quantity> amount_by_request;
              state StateMap<Name, int> ProposalStatus;
              state StateMap<Name, int> CreatedAtMs;
              state StateMap<Name, int> ExpiresAtMs;

              fn run_impl(Json ev) -> Option<bool> {{
                let request_id = ev.get_name(Name::parse("request_id"))?;
                require(!ProposalStatus.contains(request_id), StagedMintError::DuplicateRequest);
                let action = ev.get_name(Name::parse("action"))?;
                require(action == Name::parse("create"), StagedMintError::UnsupportedAction);
                let asset_id = ev.get_asset_definition_id(Name::parse("asset_id"))?;
                let expected_asset = AssetDefinitionId::parse("66owaQmAQMuHxPzxUN3bqZ6FJfDa");
                require(asset_id == expected_asset, StagedMintError::UnsupportedAssetDefinition);
                let to_account_id = ev.get_account_id(Name::parse("to_account_id"))?;
                require(
                  to_account_id == context::authority(),
                  StagedMintError::DestinationAccountMismatch,
                );
                let amount = ev.get_quantity(Name::parse("amount"))?;
                let requested_by_actor = ev.get_bytes_hex(Name::parse("requested_by_actor_hex"))?;
                let created_at_ms = ev.get_int(Name::parse("created_at_ms"))?;
                let expires_at_ms = ev.get_int(Name::parse("expires_at_ms"))?;
                require(amount > 0, StagedMintError::InvalidAmount);

                Requests_requested_by_actor[request_id] = requested_by_actor;
                ToAccount[request_id] = to_account_id;
                amount_by_request[request_id] = amount;
                ProposalStatus[request_id] = 1;
                CreatedAtMs[request_id] = created_at_ms;
                ExpiresAtMs[request_id] = expires_at_ms;
                Option::some(true)
              }}

              kotoage fn run(Json ev) authorize(staged_mint_request_run) {{
                require(run_impl(ev: ev).is_some(), StagedMintError::MissingOrInvalidField);
              }}
            }}
            "#,
            multisig_id = multisig_id,
        );
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(&src)
            .expect("compile staged mint-like contract");
        let (bytecode, contract_address) =
            install_trigger_contract(&mut tx, &signer1_id, &signer1, program, manifest, 6_455);
        let trigger_id: iroha_data_model::trigger::TriggerId = "staged_mint_like".parse().unwrap();
        let mut trigger_metadata = Metadata::default();
        trigger_metadata.insert(
            Name::from_str("contract_entrypoint").expect("static metadata key"),
            Json::new("run"),
        );
        trigger_metadata.insert(
            Name::from_str("contract_address").expect("static metadata key"),
            Json::new(contract_address.to_string()),
        );
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::Ivm(bytecode),
                Repeats::Indefinitely,
                multisig_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(multisig_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(trigger_metadata),
        );
        Register::trigger(trigger)
            .execute(&multisig_id, &mut tx)
            .expect("register event-argument-aware staged mint trigger");
        let args_json = format!(
            r#"{{"ev":{{"action":"create","amount":"111","asset_id":"66owaQmAQMuHxPzxUN3bqZ6FJfDa","created_at_ms":"1779225455574","expires_at_ms":"1779311855574","request_id":"mrtest","requested_by_actor_hex":"0x7b226163746f72223a226f70657261746f7231227d","to_account_id":"{multisig_id}"}}}}"#,
            multisig_id = multisig_id,
        );
        let instructions = vec![InstructionBox::from(
            ExecuteTrigger::new(trigger_id)
                .with_args(Json::from_raw_json(args_json).expect("valid event arguments JSON")),
        )];
        let instructions_hash = HashOf::new(&instructions);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("signatory propose staged mint");
        execute_approve(
            &mut tx,
            &signer2_id,
            &MultisigApprove::new(multisig_id.clone(), instructions_hash),
        )
        .expect("signatory approve should execute staged mint trigger");
        assert!(
            proposal_state(&tx, &multisig_id, &instructions_hash).is_err(),
            "finalized proposal should be pruned from active proposal state"
        );
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(
                    &multisig_id,
                    &instructions_hash,
                ))
                .is_some(),
            "finalized proposal should leave terminal proposal state"
        );
        let statuses =
            durable_state_values_under_contract_prefix(&tx, &contract_address, "ProposalStatus");
        assert_eq!(
            statuses.len(),
            1,
            "staged mint trigger should write one visible ProposalStatus entry"
        );
        assert_eq!(
            durable_int_value(&statuses[0]),
            1,
            "staged mint trigger should persist pending status"
        );
    }
    #[test]
    fn multisig_propose_rejects_terminal_identity_and_accepts_fresh_semantic_payload() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_with_chain(
            World::new(),
            kura,
            query_handle,
            ChainId::from("multisig-expired-duplicate-replace"),
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("retryable", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let spec = MultisigSpec {
            signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            quorum: NonZeroU16::new(2).unwrap(),
            transaction_ttl_ms: NonZeroU64::new(1).unwrap(),
        };
        let multisig_id = {
            let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 1, 0);
            let mut block = state.block(block_header);
            let mut tx = block.transaction();
            domain!(tx, signer1_id, domain_id, "domain registration");
            account!(tx, signer1_id, domain_id, signer1_id, "register signer1");
            account!(tx, signer1_id, domain_id, signer2_id, "register signer2");
            let multisig_id = msig!(tx, signer1_id, domain_id, spec, "register multisig account");
            let instructions = Vec::<InstructionBox>::new();
            execute_propose(
                &mut tx,
                &signer1_id,
                &MultisigPropose::new(multisig_id.clone(), instructions, None),
            )
            .expect("initial propose");
            tx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit first block");
            multisig_id
        };
        let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 3, 0);
        let mut block = state.block(block_header);
        let mut tx = block.transaction();
        let instructions = Vec::<InstructionBox>::new();
        let instructions_hash = HashOf::new(&instructions);
        let rejected = execute_propose(
            &mut tx,
            &signer2_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect_err("expired proposal identity cannot be reused");
        assert!(matches!(rejected, ValidationFail::NotPermitted(message)
            if message.contains("instruction identity is already terminal")));
        assert!(proposal_value(&tx, &multisig_id, &instructions_hash).is_err());
        let terminal_bytes = tx
            .world
            .smart_contract_state
            .get(&multisig_proposal_terminal_state_key(
                &multisig_id,
                &instructions_hash,
            ))
            .expect("original expired tombstone")
            .clone();
        let terminal = norito::decode_from_bytes::<MultisigProposalTerminalState>(&terminal_bytes)
            .expect("original terminal identity decodes");
        assert_eq!(terminal.status, MultisigProposalTerminalStatus::Expired);
        let instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "fresh semantic request after expiry".to_owned(),
        ))];
        let fresh_hash = HashOf::new(&instructions);
        assert_ne!(fresh_hash, instructions_hash);
        execute_propose(
            &mut tx,
            &signer2_id,
            &MultisigPropose::new(multisig_id.clone(), instructions, None),
        )
        .expect("fresh semantic request may collect approvals");
        let proposal = proposal_value(&tx, &multisig_id, &fresh_hash).expect("fresh proposal");
        assert_eq!(proposal.proposed_at_ms, 3);
        assert_eq!(proposal.expires_at_ms, 4);
        assert_eq!(
            proposal.approvals,
            BTreeSet::from([signer2_id.clone()]),
            "fresh proposal should record only the new proposer approval"
        );
        assert_eq!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(
                    &multisig_id,
                    &instructions_hash
                )),
            Some(&terminal_bytes),
            "fresh proposal must retain original history"
        );
        let canceled = MultisigProposalTerminalState::new(
            multisig_id.clone(),
            fresh_hash,
            proposal,
            MultisigProposalTerminalStatus::Canceled,
            3,
        );
        store_multisig_proposal_terminal_state(&mut tx, &canceled).unwrap();
        prune_down(&mut tx, &multisig_id, &fresh_hash).unwrap();
        let rejected = execute_propose(
            &mut tx,
            &signer2_id,
            &MultisigPropose::new(multisig_id, canceled.proposal.instructions, None),
        )
        .expect_err("canceled identity cannot be reused");
        assert!(matches!(rejected, ValidationFail::NotPermitted(message)
            if message.contains("instruction identity is already terminal")));
    }
    #[test]
    fn multisig_register_accepts_cross_domain_signatory_subjects() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-cross-domain-signatories"
        );
        let multisig_domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("multisig-home", "universal").unwrap();
        let signer_domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("signatory-remote", "universal").unwrap();
        let owner = checked_keypair();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let owner_id = new_account_id(&owner);
        let signer1_remote = new_account_id(&signer1);
        let signer2_remote = new_account_id(&signer2);
        domain!(tx, owner_id, multisig_domain, "register multisig domain");
        domain!(tx, owner_id, signer_domain, "register signer domain");
        account!(tx, owner_id, multisig_domain, owner_id, "register owner");
        account!(
            tx,
            owner_id,
            signer_domain,
            signer1_remote,
            "register signer1 remote"
        );
        account!(
            tx,
            owner_id,
            signer_domain,
            signer2_remote,
            "register signer2 remote"
        );
        assert_eq!(
            domain_owner(&tx, &multisig_domain).expect("domain owner lookup"),
            owner_id,
            "multisig domain owner should follow registering authority",
        );
        let spec = spec(
            BTreeMap::from([(signer1_remote.clone(), 1), (signer2_remote.clone(), 1)]),
            2,
        );
        let multisig_seed = new_account_id(&checked_keypair());
        let register = MultisigRegister::with_account(
            multisig_seed.clone(),
            multisig_domain.clone(),
            spec.clone(),
        );
        execute_register(&mut tx, &owner_id, register)
            .expect("register multisig from cross-domain signatories");
        let registered_multisig_id = tx
            .world
            .accounts_iter()
            .find(|account| account.id().multisig_policy().is_some())
            .map(|account| account.id().clone())
            .expect("registered multisig account");
        let stored_spec = multisig_spec(&tx, &registered_multisig_id).expect("stored spec");
        assert!(
            stored_spec
                .signatories
                .keys()
                .any(|account| account.subject_id() == signer1_remote.subject_id()),
            "remote signatory subject must be preserved in multisig spec"
        );
        assert!(
            stored_spec
                .signatories
                .keys()
                .any(|account| account.subject_id() == signer2_remote.subject_id()),
            "remote signatory subject must be preserved in multisig spec"
        );
        assert_eq!(
            multisig_home_domain(&tx, &registered_multisig_id).expect("multisig home domain"),
            Some(multisig_domain),
            "registered multisig must retain the explicit home domain"
        );
        let instructions: Vec<InstructionBox> = Vec::new();
        let instructions_hash = HashOf::new(&instructions);
        execute_propose(
            &mut tx,
            &signer1_remote,
            &MultisigPropose::new(registered_multisig_id.clone(), instructions, None),
        )
        .expect("remote-domain signatory should be able to propose by subject");
        execute_approve(
            &mut tx,
            &signer2_remote,
            &MultisigApprove::new(registered_multisig_id.clone(), instructions_hash),
        )
        .expect("remote-domain signatory should be able to approve by subject");
    }
    #[test]
    fn multisig_approval_counts_subject_once_with_multiple_domain_links() {
        tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-unique-subject-approvals"
        );
        let home_domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("subject-home", "universal").unwrap();
        let alt_domain: iroha_model_base::domain::DomainId =
            DomainId::try_new("subject-alt", "universal").unwrap();
        let owner = checked_keypair();
        let shared_subject = checked_keypair();
        let signer_b = checked_keypair();
        let signer_c = checked_keypair();
        let owner_id = new_account_id(&owner);
        let shared_account = new_account_id(&shared_subject);
        let signer_b_id = new_account_id(&signer_b);
        let signer_c_id = new_account_id(&signer_c);
        domain!(tx, owner_id, home_domain, "register home domain");
        domain!(tx, owner_id, alt_domain, "register alt domain");
        for account in [
            owner_id.clone(),
            shared_account.clone(),
            signer_b_id.clone(),
            signer_c_id.clone(),
        ] {
            account!(tx, owner_id, home_domain, account, "register account");
        }
        assert_eq!(
            domain_owner(&tx, &home_domain).expect("domain owner lookup"),
            owner_id,
            "home domain owner should follow registering authority",
        );
        let spec = spec(
            BTreeMap::from([
                (shared_account.clone(), 1),
                (signer_b_id.clone(), 1),
                (signer_c_id.clone(), 1),
            ]),
            3,
        );
        let multisig_seed = new_account_id(&checked_keypair());
        execute_register(
            &mut tx,
            &owner_id,
            MultisigRegister::with_account(multisig_seed, home_domain.clone(), spec.clone()),
        )
        .expect("register multisig");
        let multisig_account = tx
            .world
            .accounts_iter()
            .find(|account| account.id().multisig_policy().is_some())
            .map(|account| account.id().clone())
            .expect("registered multisig account");
        let instructions: Vec<InstructionBox> = Vec::new();
        let instructions_hash = HashOf::new(&instructions);
        let loaded_spec = multisig_spec(&tx, &multisig_account).expect("load multisig spec");
        execute_propose(
            &mut tx,
            &signer_b_id,
            &MultisigPropose::new(multisig_account.clone(), instructions, None),
        )
        .expect("propose");
        let proposed = proposal_value(&tx, &multisig_account, &instructions_hash)
            .expect("proposal exists after propose");
        assert_eq!(
            approved_weight_by_subject(&loaded_spec, &proposed.approvals),
            1,
            "proposer should contribute one distinct subject weight"
        );
        execute_approve(
            &mut tx,
            &shared_account,
            &MultisigApprove::new(multisig_account.clone(), instructions_hash),
        )
        .expect("approve from subject home account");
        let approved_once = proposal_value(&tx, &multisig_account, &instructions_hash)
            .expect("proposal exists after first subject approval");
        assert_eq!(
            approved_weight_by_subject(&loaded_spec, &approved_once.approvals),
            2,
            "subject approval should increase distinct subject weight"
        );
        execute_approve(
            &mut tx,
            &shared_account,
            &MultisigApprove::new(multisig_account.clone(), instructions_hash),
        )
        .expect("approve from subject with additional domain link");
        let approved_twice = proposal_value(&tx, &multisig_account, &instructions_hash)
            .expect("proposal should persist after duplicate-subject approval");
        assert_eq!(
            approved_weight_by_subject(&loaded_spec, &approved_twice.approvals),
            2,
            "same subject with multiple domain links must not satisfy quorum twice"
        );
        execute_approve(
            &mut tx,
            &signer_c_id,
            &MultisigApprove::new(multisig_account.clone(), instructions_hash),
        )
        .expect("approve from third signatory");
        assert!(
            matches!(
                proposal_value(&tx, &multisig_account, &instructions_hash),
                Err(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
            ),
            "proposal should be pruned after quorum is reached by distinct subjects"
        );
    }
    #[test]
    fn multisig_signatories_must_be_single_accounts() {
        runtime_tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-signatories-single"
        );
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("signatory-single", "universal").unwrap();
        let (owner, leaf_a, leaf_b) = (checked_keypair(), checked_keypair(), checked_keypair());
        let owner_id = new_account_id(&owner);
        let first_leaf_account_id = new_account_id(&leaf_a);
        let second_leaf_account_id = new_account_id(&leaf_b);
        domain!(tx, owner_id, domain_id, "domain registration");
        for (account_id, label) in [
            (owner_id.clone(), "register owner"),
            (first_leaf_account_id.clone(), "register leaf a"),
            (second_leaf_account_id.clone(), "register leaf b"),
        ] {
            register_account_in_domain(&mut tx, &owner_id, &domain_id, &account_id, label);
        }
        let child_spec = spec(
            BTreeMap::from([
                (first_leaf_account_id.clone(), 1),
                (second_leaf_account_id.clone(), 1),
            ]),
            2,
        );
        let child_id = msig!(
            tx,
            owner_id,
            domain_id,
            child_spec,
            "register child multisig account"
        );
        let parent_spec = spec(
            BTreeMap::from([(owner_id.clone(), 1), (child_id.clone(), 1)]),
            2,
        );
        let parent_key = checked_keypair();
        let parent_id = new_account_id(&parent_key);
        let register = MultisigRegister::with_account(parent_id, domain_id.clone(), parent_spec);
        let err = Executor::Initial
            .execute_instruction(&mut tx, &owner_id, InstructionBox::from(register))
            .expect_err("multisig signatory must be single");
        match err {
            ValidationFail::NotPermitted(msg) => {
                assert!(
                    msg.contains("single-key account"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn multisig_deferred_execution_reenters_active_executor_and_preserves_valid_flow() {
        runtime_tx!(
            state,
            block,
            tx,
            World::new(),
            "multisig-deferred-active-executor",
            0
        );
        let domain_id = DomainId::try_new("deferred", "universal").expect("domain id");
        let signer_id = new_account_id(&checked_keypair());
        domain!(
            tx,
            signer_id,
            domain_id,
            "register deferred-execution domain"
        );
        account!(
            tx,
            signer_id,
            domain_id,
            signer_id,
            "register deferred-execution signer"
        );
        let spec = MultisigSpec {
            signatories: BTreeMap::from([(signer_id.clone(), 1)]),
            quorum: NonZeroU16::new(1).expect("non-zero quorum"),
            transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).expect("non-zero ttl"),
        };
        let multisig_id = msig!(
            tx,
            signer_id,
            domain_id,
            spec,
            "register deferred-execution multisig"
        );
        let metadata_key: Name = "deferred_executor_valid".parse().expect("metadata key");
        let metadata_value = Json::new("validated");
        let valid_instructions = vec![InstructionBox::from(SetKeyValue::account(
            multisig_id.clone(),
            metadata_key.clone(),
            metadata_value.clone(),
        ))];
        let valid_hash = HashOf::new(&valid_instructions);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer_id,
                MultisigPropose::new(multisig_id.clone(), valid_instructions, None).into(),
            )
            .expect("propose valid deferred instruction");
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer_id,
                MultisigApprove::new(multisig_id.clone(), valid_hash).into(),
            )
            .expect("active initial executor should allow self-owned metadata mutation");
        assert_eq!(
            tx.world
                .account(&multisig_id)
                .expect("multisig account")
                .metadata()
                .get(&metadata_key),
            Some(&metadata_value),
            "a valid deferred instruction should still execute"
        );
        let privileged_permission: Permission =
            iroha_executor_data_model::permission::executor::CanUpgradeExecutor.into();
        let privileged_instructions = vec![InstructionBox::from(Grant::account_permission(
            privileged_permission.clone(),
            signer_id.clone(),
        ))];
        let privileged_hash = HashOf::new(&privileged_instructions);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer_id,
                MultisigPropose::new(multisig_id.clone(), privileged_instructions, None).into(),
            )
            .expect("propose privileged deferred instruction");
        let privileged_error = Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer_id,
                MultisigApprove::new(multisig_id.clone(), privileged_hash).into(),
            )
            .expect_err("multisig must not bypass genesis-only permission delegation");
        assert!(
            matches!(&privileged_error, ValidationFail::NotPermitted(_)),
            "unexpected privileged-instruction error: {privileged_error:?}"
        );
        assert!(
            !tx.world
                .account_permissions_iter(&signer_id)
                .expect("signer permissions")
                .any(|permission| permission == &privileged_permission),
            "denied deferred grant must not mutate permissions"
        );
        let denied_instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "deferred instruction must reach the active executor".to_owned(),
        ))];
        let denied_hash = HashOf::new(&denied_instructions);
        Executor::Initial
            .execute_instruction(
                &mut tx,
                &signer_id,
                MultisigPropose::new(multisig_id.clone(), denied_instructions, None).into(),
            )
            .expect("propose instruction before executor replacement");
        *tx.world.executor.get_mut() =
            crate::executor::denying_executor_for_testing("deferred instruction denied");
        let denied_error = execute_approve(
            &mut tx,
            &signer_id,
            &MultisigApprove::new(multisig_id, denied_hash),
        )
        .expect_err("final approval must submit stored instructions to the active executor");
        assert_eq!(
            denied_error,
            ValidationFail::NotPermitted("deferred instruction denied".to_owned())
        );
        assert!(
            tx.multisig_deferred_execution_stack.is_empty(),
            "failed deferred execution must unwind its recursion guard"
        );
    }
    #[test]
    fn multisig_deferred_execution_guard_rejects_cycles_and_excessive_depth() {
        let account = new_account_id(&checked_keypair());
        let first_hash = HashOf::new(&vec![InstructionBox::from(Log::new(
            Level::INFO,
            "cycle".to_owned(),
        ))]);
        let first_id = (account.clone(), first_hash);
        let mut execution_stack = Vec::new();
        begin_multisig_deferred_execution(&mut execution_stack, &first_id)
            .expect("first proposal may execute");
        let cycle_error = begin_multisig_deferred_execution(&mut execution_stack, &first_id)
            .expect_err("an active proposal may not recursively execute itself");
        assert!(matches!(cycle_error, ValidationFail::NotPermitted(_)));
        finish_multisig_deferred_execution(&mut execution_stack, &first_id);
        let mut execution_ids = Vec::with_capacity(MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH);
        for depth in 0..MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH {
            let hash = HashOf::new(&vec![InstructionBox::from(Log::new(
                Level::INFO,
                format!("depth-{depth}"),
            ))]);
            let execution_id = (account.clone(), hash);
            begin_multisig_deferred_execution(&mut execution_stack, &execution_id)
                .expect("proposal within the deferred execution depth bound");
            execution_ids.push(execution_id);
        }
        let beyond_limit = (
            account,
            HashOf::new(&vec![InstructionBox::from(Log::new(
                Level::INFO,
                "beyond-limit".to_owned(),
            ))]),
        );
        assert_eq!(
            begin_multisig_deferred_execution(&mut execution_stack, &beyond_limit),
            Err(ValidationFail::TooComplex)
        );
        for execution_id in execution_ids.iter().rev() {
            finish_multisig_deferred_execution(&mut execution_stack, execution_id);
        }
        assert!(execution_stack.is_empty());
    }
    #[test]
    fn multisig_expiry_traversal_rejects_cycles_and_excessive_depth() {
        let member_key = checked_keypair();
        let member =
            MultisigMember::new(member_key.public_key().clone(), 1).expect("multisig member");
        let policy = MultisigPolicy::new(1, vec![member]).expect("multisig policy");
        let multisig_id = AccountId::new_multisig(policy);
        let owner_id = new_account_id(&checked_keypair());
        let world = World::with([], [Account::new(multisig_id.clone()).build(&owner_id)], []);
        tx!(
            state,
            block,
            tx,
            world,
            "multisig-expiry-traversal-guard",
            1_u64,
            1
        );
        let cycle_hash = HashOf::new(&Vec::<InstructionBox>::new());
        let cycle_instruction = MultisigApprove::new(multisig_id.clone(), cycle_hash);
        store_multisig_proposal_state(
            &mut tx,
            &MultisigProposalState::new(
                multisig_id.clone(),
                cycle_hash,
                vec![cycle_instruction.into()],
                0,
                0,
                BTreeSet::new(),
                None,
            ),
        )
        .expect("store cyclic proposal state");
        let cycle_error = prune_expired(&mut tx, &multisig_id, &cycle_hash, &multisig_id)
            .expect_err("cyclic expiry traversal must fail closed");
        assert_eq!(
            cycle_error,
            invalid_proposal_binding(),
            "a fabricated hash cycle fails its content binding before traversal"
        );
        // Build from the leaf upward: every physical row binds its actual child approval.
        let mut child = None;
        for depth in (0..=MAX_MULTISIG_DEFERRED_EXECUTION_DEPTH).rev() {
            let instructions = child.map_or_else(
                || {
                    vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        format!("expiry-depth-{depth}"),
                    ))]
                },
                |hash| {
                    vec![InstructionBox::from(MultisigApprove::new(
                        multisig_id.clone(),
                        hash,
                    ))]
                },
            );
            let hash = HashOf::new(&instructions);
            store_multisig_proposal_state(
                &mut tx,
                &MultisigProposalState::new(
                    multisig_id.clone(),
                    hash,
                    instructions,
                    0,
                    0,
                    BTreeSet::new(),
                    None,
                ),
            )
            .expect("store exact deep proposal state");
            child = Some(hash);
        }
        let depth_error = prune_expired(&mut tx, &multisig_id, &child.unwrap(), &multisig_id)
            .expect_err("expiry traversal beyond the deterministic depth bound must fail");
        assert_eq!(depth_error, ValidationFail::TooComplex);
    }
    #[test]
    fn multisig_spec_missing_metadata_returns_error() {
        tx!(state, block, tx, World::new(), "multisig-missing-spec");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("missing", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let err = multisig_spec(&tx, &owner_id).expect_err("missing multisig spec should error");
        match err {
            ValidationFail::QueryFailed(QueryExecutionFail::NotFound) => {}
            other => panic!("unexpected error for missing multisig spec: {other:?}"),
        }
    }
    #[test]
    fn multisig_role_for_large_policy_uses_hash_suffix() {
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("weights", "universal").unwrap();
        let member_count = (u8::MAX as usize) + 1;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            let key = checked_keypair();
            let member = MultisigMember::new(key.public_key().clone(), 1).expect("multisig member");
            members.push(member);
        }
        let policy = MultisigPolicy::new(1, members).expect("multisig policy");
        let account = AccountId::new_multisig(policy);
        let canonical = account
            .canonical_i105()
            .expect("large multisig policy should encode into canonical I105");
        let role_id = multisig_role_for(Some(&domain_id), &account);
        let role_name = role_id.name().to_string();
        let expected_suffix = HashOf::new(&account).to_string();
        assert!(
            role_name.ends_with(&expected_suffix),
            "role name should use hash suffix for large multisig policy"
        );
        assert!(
            !role_name.ends_with(&canonical),
            "large multisig role ids should still fall back to the hash suffix when the canonical literal is too long"
        );
    }
    #[test]
    fn multisig_approval_weight_sum_does_not_overflow() {
        runtime_tx!(state, block, tx, World::new(), "multisig-weight-overflow");
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("weights", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(tx, owner_id, domain_id, owner_id, "register owner");
        let weight = u8::MAX;
        let signatory_count = (u16::MAX as usize / weight as usize) + 1;
        let mut signatories = BTreeMap::new();
        for _ in 0..signatory_count {
            let signer_key = checked_keypair();
            let signer_id = new_account_id(&signer_key);
            account!(tx, owner_id, domain_id, signer_id, "register signatory");
            signatories.insert(signer_id, weight);
        }
        let spec = spec(signatories.clone(), u16::MAX);
        let multisig_id = msig!(tx, owner_id, domain_id, spec, "register multisig account");
        let instructions: Vec<InstructionBox> = Vec::new();
        let instructions_hash = HashOf::new(&instructions);
        let proposer = signatories
            .keys()
            .next()
            .expect("signatories present")
            .clone();
        let proposal = MultisigPropose::new(multisig_id.clone(), instructions, None);
        Executor::Initial
            .execute_instruction(&mut tx, &proposer, InstructionBox::from(proposal))
            .expect("multisig propose");
        let mut seeded_value =
            proposal_value(&tx, &multisig_id, &instructions_hash).expect("proposal value");
        seeded_value.approvals = signatories.keys().cloned().collect();
        store_multisig_proposal_state(
            &mut tx,
            &MultisigProposalState::new(
                multisig_id.clone(),
                instructions_hash,
                seeded_value.instructions,
                seeded_value.proposed_at_ms,
                seeded_value.expires_at_ms,
                seeded_value.approvals,
                seeded_value.is_relayed,
            ),
        )
        .expect("seed approvals");
        let approver = signatories
            .keys()
            .next_back()
            .expect("signatories present")
            .clone();
        let approve = MultisigApprove::new(multisig_id.clone(), instructions_hash);
        Executor::Initial
            .execute_instruction(&mut tx, &approver, InstructionBox::from(approve))
            .expect("multisig approve");
        assert!(
            proposal_value(&tx, &multisig_id, &instructions_hash).is_err(),
            "proposal should be pruned after reaching quorum"
        );
    }
    #[test]
    fn replace_account_controller_single_to_multisig_materializes_members_and_preserves_alias() {
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("replace", "universal").unwrap();
        let owner_key = checked_keypair();
        let owner_id = new_account_id(&owner_key);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut world = World::new();
        seed_domain_name_lease(&mut world, &owner_id, &domain_id);
        let state = State::new_with_chain(
            world,
            kura,
            query_handle,
            ChainId::from("replace-single-to-multisig"),
        );
        let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(block_header);
        let mut tx = block.transaction();
        domain!(tx, owner_id, domain_id, "domain registration");
        account!(
            tx,
            owner_id,
            domain_id,
            owner_id,
            "register single-key account"
        );
        let alias = bind_account_label(&mut tx, &owner_id, &owner_id, &domain_id, "treasury");
        let member1 = checked_keypair();
        let member2 = checked_keypair();
        let policy = multisig_policy_for_members(&[(&member1, 1), (&member2, 1)]);
        let updated_account = replace_account_controller(
            &owner_id,
            &mut tx,
            &owner_id,
            AccountController::multisig(policy),
        )
        .expect("replace single-key controller with multisig");
        assert!(
            multisig_spec(&tx, &updated_account).is_ok(),
            "multisig replacement should persist native multisig state"
        );
        assert!(
            tx.world
                .account(&AccountId::new(member1.public_key().clone()))
                .is_ok(),
            "first signatory account should be materialized"
        );
        assert!(
            tx.world
                .account(&AccountId::new(member2.public_key().clone()))
                .is_ok(),
            "second signatory account should be materialized"
        );
        assert_eq!(tx.world.account_aliases.get(&alias), Some(&updated_account));
        assert_eq!(
            tx.world
                .account_rekey_records
                .get(&alias)
                .expect("rekey record should remain")
                .active_account_id,
            updated_account
        );
    }
    #[test]
    fn replace_account_controller_multisig_to_single_clears_memberships() {
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("single", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut world = World::new();
        seed_domain_name_lease(&mut world, &signer1_id, &domain_id);
        let state = State::new_with_chain(
            world,
            kura,
            query_handle,
            ChainId::from("replace-multisig-to-single"),
        );
        let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(block_header);
        let mut tx = block.transaction();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&signer1_id, &mut tx)
            .expect("domain registration");
        for (account_id, label) in [
            (&signer1_id, "register signer1"),
            (&signer2_id, "register signer2"),
        ] {
            register_account_in_domain(&mut tx, &signer1_id, &domain_id, account_id, label);
        }
        let spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(tx, signer1_id, domain_id, spec, "register multisig account");
        let alias = bind_account_label(&mut tx, &signer1_id, &multisig_id, &domain_id, "payments");
        let replacement_key = checked_keypair();
        let replacement_account = AccountId::new(replacement_key.public_key().clone());
        let updated_account = replace_account_controller(
            &signer1_id,
            &mut tx,
            &multisig_id,
            AccountController::single(replacement_key.public_key().clone()),
        )
        .expect("replace multisig controller with single-key");
        assert_eq!(updated_account, replacement_account);
        assert_eq!(
            load_signatory_memberships(&tx, &signer1_id),
            BTreeSet::new()
        );
        assert_eq!(
            load_signatory_memberships(&tx, &signer2_id),
            BTreeSet::new()
        );
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_account_state_key(&updated_account))
                .is_none(),
            "single-key replacement should clear native multisig state"
        );
        assert_eq!(tx.world.account_aliases.get(&alias), Some(&updated_account));
    }
    #[test]
    fn replace_account_controller_requires_invalidation_and_retains_original_terminal_history() {
        let domain_id: iroha_model_base::domain::DomainId =
            DomainId::try_new("repoint", "universal").unwrap();
        let signer1 = checked_keypair();
        let signer2 = checked_keypair();
        let signer3 = checked_keypair();
        let signer1_id = new_account_id(&signer1);
        let signer2_id = new_account_id(&signer2);
        let signer3_id = new_account_id(&signer3);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let mut world = World::new();
        seed_domain_name_lease(&mut world, &signer1_id, &domain_id);
        let state = State::new_with_chain(
            world,
            kura,
            query_handle,
            ChainId::from("replace-multisig-to-multisig"),
        );
        let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 1_000, 0);
        let mut block = state.block(block_header);
        let mut tx = block.transaction();
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&signer1_id, &mut tx)
            .expect("domain registration");
        for (account_id, label) in [
            (&signer1_id, "register signer1"),
            (&signer2_id, "register signer2"),
            (&signer3_id, "register signer3"),
        ] {
            register_account_in_domain(&mut tx, &signer1_id, &domain_id, account_id, label);
        }
        let initial_spec = spec(
            BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
            2,
        );
        let multisig_id = msig!(
            tx,
            signer1_id,
            domain_id,
            initial_spec,
            "register multisig account"
        );
        let outstanding_instructions = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "pending request cannot inherit replacement approvals".to_owned(),
        ))];
        let outstanding_hash = HashOf::new(&outstanding_instructions);
        execute_propose(
            &mut tx,
            &signer1_id,
            &MultisigPropose::new(multisig_id.clone(), outstanding_instructions, None),
        )
        .expect("create outstanding proposal before ordinary rekey");
        let replacement_policy = multisig_policy_for_members(&[(&signer2, 1), (&signer3, 1)]);
        let rejected = replace_account_controller(
            &signer1_id,
            &mut tx,
            &multisig_id,
            AccountController::multisig(replacement_policy.clone()),
        )
        .expect_err("replacement must first invalidate outstanding proposals");
        assert!(
            matches!(rejected, InstructionExecutionError::InvalidParameter(
            InvalidParameterError::SmartContract(message))
            if message.contains("outstanding multisig proposal invalidation"))
        );
        assert!(proposal_state(&tx, &multisig_id, &outstanding_hash).is_ok());
        assert!(tx.world.accounts.get(&multisig_id).is_some());
        execute_invalidate_outstanding(
            &mut tx,
            &multisig_id,
            &MultisigInvalidateOutstanding::new(multisig_id.clone()),
        )
        .expect("owner invalidates old approvals atomically before replacement");
        let original_terminal = tx
            .world
            .smart_contract_state
            .get(&multisig_proposal_terminal_state_key(
                &multisig_id,
                &outstanding_hash,
            ))
            .expect("original canceled evidence")
            .clone();
        let historical =
            norito::decode_from_bytes::<MultisigProposalTerminalState>(&original_terminal)
                .expect("original controller history decodes");
        assert_eq!(historical.multisig_account_id, multisig_id);
        assert_eq!(historical.status, MultisigProposalTerminalStatus::Canceled);
        assert_eq!(historical.terminal_at_ms, 1_000);
        assert_eq!(
            historical.proposal.approvals,
            BTreeSet::from([signer1_id.clone()])
        );
        let updated_account = replace_account_controller(
            &signer1_id,
            &mut tx,
            &multisig_id,
            AccountController::multisig(replacement_policy),
        )
        .expect("replace multisig controller with new multisig policy");
        assert_eq!(
            load_signatory_memberships(&tx, &signer1_id),
            BTreeSet::new()
        );
        assert_eq!(
            load_signatory_memberships(&tx, &signer2_id),
            BTreeSet::from([updated_account.clone()])
        );
        assert_eq!(
            load_signatory_memberships(&tx, &signer3_id),
            BTreeSet::from([updated_account.clone()])
        );
        let updated_spec = multisig_spec(&tx, &updated_account)
            .expect("updated multisig spec should be available");
        assert_eq!(
            updated_spec
                .signatories
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([signer2_id, signer3_id])
        );
        assert!(
            proposal_state(&tx, &multisig_id, &outstanding_hash).is_err(),
            "ordinary rekey must remove the old-account proposal key",
        );
        assert!(
            proposal_state(&tx, &updated_account, &outstanding_hash).is_err(),
            "replacement policy must never inherit old approvals"
        );
        assert_eq!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(
                    &multisig_id,
                    &outstanding_hash
                )),
            Some(&original_terminal),
            "original policy history survives controller replacement"
        );
        assert!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(
                    &updated_account,
                    &outstanding_hash
                ))
                .is_none()
        );
    }
}
