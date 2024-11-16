//! Validation and execution logic of instructions for multisig transactions

use alloc::{collections::btree_set::BTreeSet, vec};
use core::num::NonZeroU64;

use iroha_smart_contract::data_model::query::error::QueryExecutionFail;

use super::*;

impl VisitExecute for MultisigPropose {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
        let host = executor.host();
        let proposer = executor.context().authority.clone();
        let multisig_account = self.account.clone();
        let instructions_hash = HashOf::new(&self.instructions);
        let multisig_spec = match multisig_spec(multisig_account.clone(), executor) {
            Ok(spec) => spec,
            Err(err) => deny!(executor, err),
        };
        let is_downward_proposal = host
            .query(FindRolesByAccountId::new(multisig_account.clone()))
            .filter_with(|role_id| role_id.eq(multisig_role_for(&proposer)))
            .execute_single()
            .is_ok();
        let has_multisig_role = host
            .query(FindRolesByAccountId::new(proposer))
            .filter_with(|role_id| role_id.eq(multisig_role_for(&multisig_account)))
            .execute_single()
            .is_ok();
        let has_not_longer_ttl = self.transaction_ttl_ms.map_or(true, |override_ttl_ms| {
            override_ttl_ms <= multisig_spec.transaction_ttl_ms
        });

        if !(is_downward_proposal || has_not_longer_ttl) {
            deny!(executor, "ttl violates the restriction");
        };

        if !(is_downward_proposal || has_multisig_role) {
            deny!(executor, "not qualified to propose multisig");
        };

        if host
            .query_single(FindAccountMetadata::new(
                multisig_account,
                proposal_key(&instructions_hash),
            ))
            .is_ok()
        {
            deny!(executor, "multisig proposal duplicates")
        };
    }

    fn execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) -> Result<(), ValidationFail> {
        let proposer = executor.context().authority.clone();
        let multisig_account = self.account;
        let instructions_hash = HashOf::new(&self.instructions);
        let spec = multisig_spec(multisig_account.clone(), executor)?;

        let now_ms = now_ms(executor);
        let expires_at_ms = {
            let ttl_ms = self.transaction_ttl_ms.unwrap_or(spec.transaction_ttl_ms);
            now_ms.saturating_add(ttl_ms.into())
        };
        let proposal_value = MultisigProposalValue::new(
            self.instructions,
            now_ms,
            expires_at_ms,
            BTreeSet::from([proposer]),
            None,
        );
        let relay_value = |relay: MultisigApprove| {
            MultisigProposalValue::new(
                vec![relay.into()],
                now_ms,
                expires_at_ms,
                BTreeSet::new(),
                Some(false),
            )
        };

        let approve_me = MultisigApprove::new(multisig_account.clone(), instructions_hash);
        // Recursively deploy multisig authentication down to the personal leaf signatories
        for signatory in spec.signatories.keys().cloned() {
            if is_multisig(&signatory, executor) {
                deploy_relayer(signatory, approve_me.clone(), relay_value, executor)?;
            }
        }

        // Authorize as the multisig account
        executor.context_mut().authority = multisig_account.clone();

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account,
            proposal_key(&instructions_hash),
            Json::new(&proposal_value),
        )));

        Ok(())
    }
}

fn deploy_relayer<V: Execute + Visit + ?Sized>(
    relayer: AccountId,
    relay: MultisigApprove,
    relay_value: impl Fn(MultisigApprove) -> MultisigProposalValue + Clone,
    executor: &mut V,
) -> Result<(), ValidationFail> {
    let spec = multisig_spec(relayer.clone(), executor)?;

    let relay_hash = HashOf::new(&vec![relay.clone().into()]);
    let sub_relay = MultisigApprove::new(relayer.clone(), relay_hash);

    for signatory in spec.signatories.keys().cloned() {
        if is_multisig(&signatory, executor) {
            deploy_relayer(signatory, sub_relay.clone(), relay_value.clone(), executor)?;
        }
    }

    // Authorize as the relayer account
    executor.context_mut().authority = relayer.clone();

    visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
        relayer,
        proposal_key(&relay_hash),
        Json::new(relay_value(relay)),
    )));

    Ok(())
}

fn is_multisig<V: Execute + Visit + ?Sized>(account: &AccountId, executor: &V) -> bool {
    executor
        .host()
        .query(FindRoleIds)
        .filter_with(|role_id| role_id.eq(multisig_role_for(account)))
        .execute_single_opt()
        .dbg_unwrap()
        .is_some()
}

fn multisig_spec<V: Execute + Visit + ?Sized>(
    multisig_account: AccountId,
    executor: &V,
) -> Result<MultisigSpec, ValidationFail> {
    executor
        .host()
        .query_single(FindAccountMetadata::new(multisig_account, spec_key()))?
        .try_into_any()
        .map_err(metadata_conversion_error)
}

fn proposal_value<V: Execute + Visit + ?Sized>(
    multisig_account: AccountId,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    executor: &V,
) -> Result<MultisigProposalValue, ValidationFail> {
    executor
        .host()
        .query_single(FindAccountMetadata::new(
            multisig_account,
            proposal_key(&instructions_hash),
        ))?
        .try_into_any()
        .map_err(metadata_conversion_error)
}

fn now_ms<V: Execute + Visit + ?Sized>(executor: &V) -> NonZeroU64 {
    executor
        .context()
        .curr_block
        .creation_time()
        .as_millis()
        .try_into()
        .ok()
        .and_then(NonZeroU64::new)
        .dbg_expect("shouldn't overflow within 584942417 years")
}

impl VisitExecute for MultisigApprove {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
        let approver = executor.context().authority.clone();
        let multisig_account = self.account.clone();
        let host = executor.host();
        let instructions_hash = self.instructions_hash;

        if host
            .query(FindRolesByAccountId::new(approver))
            .filter_with(|role_id| role_id.eq(multisig_role_for(&multisig_account)))
            .execute_single()
            .is_err()
        {
            deny!(executor, "not qualified to approve multisig");
        };

        if let Err(err) = proposal_value(multisig_account, instructions_hash, executor) {
            deny!(executor, err)
        };
    }

    fn execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) -> Result<(), ValidationFail> {
        let approver = executor.context().authority.clone();
        let multisig_account = self.account;
        let instructions_hash = self.instructions_hash;

        // Check if the proposal is expired
        // Authorize as the multisig account
        prune_expired(multisig_account.clone(), instructions_hash, executor)?;

        let Ok(mut proposal_value) =
            proposal_value(multisig_account.clone(), instructions_hash, executor)
        else {
            // The proposal is pruned
            // TODO Notify that the proposal has expired, while returning Ok for the entry deletion to take effect
            return Ok(());
        };
        if let Some(true) = proposal_value.is_relayed {
            // The relaying approval already has executed
            return Ok(());
        }

        proposal_value.approvals.insert(approver);
        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            proposal_key(&instructions_hash),
            Json::new(&proposal_value),
        )));

        let spec = multisig_spec(multisig_account.clone(), executor)?;
        let is_authenticated = u16::from(spec.quorum)
            <= spec
                .signatories
                .into_iter()
                .filter(|(id, _)| proposal_value.approvals.contains(id))
                .map(|(_, weight)| u16::from(weight))
                .sum();

        if is_authenticated {
            match proposal_value.is_relayed {
                None => {
                    // Cleanup the transaction entry
                    prune_down(multisig_account, instructions_hash, executor)?;
                }
                Some(false) => {
                    // Mark the relaying approval as executed
                    proposal_value.is_relayed = Some(true);
                    visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
                        multisig_account,
                        proposal_key(&instructions_hash),
                        proposal_value.clone(),
                    )));
                }
                _ => unreachable!(),
            }

            for instruction in proposal_value.instructions {
                visit_seq!(executor.visit_instruction(&instruction));
            }
        }

        Ok(())
    }
}

/// Remove an expired proposal and relevant entries, switching the executor authority to this multisig account
fn prune_expired<V: Execute + Visit + ?Sized>(
    multisig_account: AccountId,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    executor: &mut V,
) -> Result<(), ValidationFail> {
    let proposal_value = proposal_value(multisig_account.clone(), instructions_hash, executor)?;

    if now_ms(executor) < proposal_value.expires_at_ms {
        // Authorize as the multisig account
        executor.context_mut().authority = multisig_account.clone();
        return Ok(());
    }

    // Go upstream to the root through approvals
    for instruction in proposal_value.instructions {
        if let InstructionBox::Custom(instruction) = instruction {
            if let Ok(MultisigInstructionBox::Approve(approve)) = instruction.payload().try_into() {
                return prune_expired(approve.account, approve.instructions_hash, executor);
            }
        }
    }

    // Go downstream, cleaning up relayers
    prune_down(multisig_account, instructions_hash, executor)
}

/// Remove an proposal and relevant entries, switching the executor authority to this multisig account
fn prune_down<V: Execute + Visit + ?Sized>(
    multisig_account: AccountId,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    executor: &mut V,
) -> Result<(), ValidationFail> {
    let spec = multisig_spec(multisig_account.clone(), executor)?;

    // Authorize as the multisig account
    executor.context_mut().authority = multisig_account.clone();

    visit_seq!(
        executor.visit_remove_account_key_value(&RemoveKeyValue::account(
            multisig_account.clone(),
            proposal_key(&instructions_hash),
        ))
    );

    for signatory in spec.signatories.keys().cloned() {
        let relay_hash = {
            let relay = MultisigApprove::new(multisig_account.clone(), instructions_hash);
            HashOf::new(&vec![relay.into()])
        };
        if is_multisig(&signatory, executor) {
            prune_down(signatory, relay_hash, executor)?
        }
    }

    // Restore the authority
    executor.context_mut().authority = multisig_account;

    Ok(())
}

#[expect(clippy::needless_pass_by_value)]
fn metadata_conversion_error(err: serde_json::Error) -> ValidationFail {
    ValidationFail::QueryFailed(QueryExecutionFail::Conversion(format!(
        "multisig account metadata malformed:\n{err}"
    )))
}
