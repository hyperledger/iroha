//! Validation and execution logic of instructions for multisig transactions

use alloc::collections::btree_set::BTreeSet;
use core::num::NonZeroU64;

use super::*;

impl VisitExecute for MultisigPropose {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
        let proposer = executor.context().authority.clone();
        let multisig_account = self.account.clone();
        let host = executor.host();
        let instructions_hash = HashOf::new(&self.instructions);
        let multisig_role = multisig_role_for(&multisig_account);
        let Some(multisig_spec) = host
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                spec_key(),
            ))
            .ok()
            .and_then(|json| json.try_into_any::<MultisigSpec>().ok())
        else {
            deny!(executor, "multisig spec not found or malformed");
        };

        let is_downward_proposal = host
            .query_single(FindAccountMetadata::new(proposer.clone(), spec_key()))
            .map_or(false, |json| {
                json.try_into_any::<MultisigSpec>()
                    .dbg_unwrap()
                    .signatories
                    .contains_key(&multisig_account)
            });
        let has_multisig_role = host
            .query(FindRolesByAccountId::new(proposer))
            .filter_with(|role_id| role_id.eq(multisig_role))
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
                multisig_account.clone(),
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

        // Authorize as the multisig account
        executor.context_mut().authority = multisig_account.clone();

        let instructions_hash = HashOf::new(&self.instructions);
        let now_ms = executor
            .context()
            .curr_block
            .creation_time()
            .as_millis()
            .try_into()
            .ok()
            .and_then(NonZeroU64::new)
            .dbg_expect("shouldn't overflow within 584942417 years");
        let spec: MultisigSpec = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                spec_key(),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();
        let expires_at_ms = {
            let ttl_ms = self.transaction_ttl_ms.unwrap_or(spec.transaction_ttl_ms);
            now_ms.saturating_add(ttl_ms.into())
        };
        let approvals = BTreeSet::from([proposer]);
        let proposal_value =
            MultisigProposalValue::new(self.instructions, now_ms, expires_at_ms, approvals);
        let signatories = spec.signatories;

        // Recursively deploy multisig authentication down to the personal leaf signatories
        for signatory in signatories.keys().cloned() {
            let is_multisig_again = executor
                .host()
                .query(FindRoleIds)
                .filter_with(|role_id| role_id.eq(multisig_role_for(&signatory)))
                .execute_single_opt()
                .dbg_unwrap()
                .is_some();

            if is_multisig_again {
                let propose_to_approve_me = {
                    let approve_me =
                        MultisigApprove::new(multisig_account.clone(), instructions_hash);

                    MultisigPropose::new(
                        signatory,
                        [approve_me.into()].to_vec(),
                        // Force override by the root proposal TTL
                        Some(self.transaction_ttl_ms.unwrap_or(spec.transaction_ttl_ms)),
                    )
                };
                propose_to_approve_me.visit_execute(executor);
            }
        }

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            proposal_key(&instructions_hash).clone(),
            Json::new(&proposal_value),
        )));

        Ok(())
    }
}

impl VisitExecute for MultisigApprove {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
        let approver = executor.context().authority.clone();
        let multisig_account = self.account.clone();
        let host = executor.host();
        let instructions_hash = self.instructions_hash;
        let multisig_role = multisig_role_for(&multisig_account);

        if host
            .query(FindRolesByAccountId::new(approver))
            .filter_with(|role_id| role_id.eq(multisig_role))
            .execute_single()
            .is_err()
        {
            deny!(executor, "not qualified to approve multisig");
        };

        if host
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                proposal_key(&instructions_hash),
            ))
            .is_err()
        {
            deny!(executor, "no proposals to approve")
        };
    }

    fn execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) -> Result<(), ValidationFail> {
        let approver = executor.context().authority.clone();
        let multisig_account = self.account;
        let instructions_hash = self.instructions_hash;

        // Check if the proposal is expired
        prune_expired(multisig_account.clone(), instructions_hash, executor)?;

        // Authorize as the multisig account
        executor.context_mut().authority = multisig_account.clone();

        let Some(mut proposal_value) = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                proposal_key(&instructions_hash),
            ))
            .ok()
            .and_then(|json| json.try_into_any::<MultisigProposalValue>().ok())
        else {
            // TODO Notify that the proposal has expired, while returning Ok for the entry deletion to take effect
            return Ok(());
        };

        proposal_value.approvals.insert(approver);

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            proposal_key(&instructions_hash),
            Json::new(&proposal_value),
        )));

        let spec: MultisigSpec = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                spec_key(),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();

        let is_authenticated = u16::from(spec.quorum)
            <= spec
                .signatories
                .into_iter()
                .filter(|(id, _)| proposal_value.approvals.contains(id))
                .map(|(_, weight)| u16::from(weight))
                .sum();

        if is_authenticated {
            for instruction in proposal_value.instructions {
                visit_seq!(executor.visit_instruction(&instruction));
            }

            // Cleanup the transaction entry
            visit_seq!(
                executor.visit_remove_account_key_value(&RemoveKeyValue::account(
                    multisig_account.clone(),
                    proposal_key(&instructions_hash),
                ))
            );
        }

        Ok(())
    }
}

/// Remove intermediate approvals and the root proposal if expired
fn prune_expired<V: Execute + Visit + ?Sized>(
    multisig_account: AccountId,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    executor: &mut V,
) -> Result<(), ValidationFail> {
    // Confirm entry existence
    let Some(proposal_value) = executor
        .host()
        .query_single(FindAccountMetadata::new(
            multisig_account.clone(),
            proposal_key(&instructions_hash),
        ))
        .ok()
        .and_then(|json| json.try_into_any::<MultisigProposalValue>().ok())
    else {
        // Removed by another path
        return Ok(());
    };
    // Confirm expiration
    let now_ms = executor
        .context()
        .curr_block
        .creation_time()
        .as_millis()
        .try_into()
        .ok()
        .and_then(NonZeroU64::new)
        .dbg_expect("shouldn't overflow within 584942417 years");
    if now_ms < proposal_value.expires_at_ms {
        return Ok(());
    }
    // Recurse through approvals
    for instruction in proposal_value.instructions {
        if let InstructionBox::Custom(instruction) = instruction {
            if let Ok(MultisigInstructionBox::Approve(approve)) = instruction.payload().try_into() {
                prune_expired(approve.account, approve.instructions_hash, executor)?;
            }
        }
    }
    // Authorize as the multisig account
    executor.context_mut().authority = multisig_account.clone();
    // Cleanup the transaction entry
    visit_seq!(
        executor.visit_remove_account_key_value(&RemoveKeyValue::account(
            multisig_account,
            proposal_key(&instructions_hash),
        ))
    );

    Ok(())
}
