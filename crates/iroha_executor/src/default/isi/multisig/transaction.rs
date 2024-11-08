//! Validation and execution logic of instructions for multisig transactions

use alloc::collections::{btree_map::BTreeMap, btree_set::BTreeSet};

use super::*;

impl VisitExecute for MultisigPropose {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
        let proposer = executor.context().authority.clone();
        let multisig_account = self.account.clone();
        let host = executor.host();
        let instructions_hash = HashOf::new(&self.instructions);
        let multisig_role = multisig_role_for(&multisig_account);
        let is_downward_proposal = host
            .query_single(FindAccountMetadata::new(
                proposer.clone(),
                SIGNATORIES.parse().unwrap(),
            ))
            .map_or(false, |proposer_signatories| {
                proposer_signatories
                    .try_into_any::<BTreeMap<AccountId, u8>>()
                    .dbg_unwrap()
                    .contains_key(&multisig_account)
            });
        let has_multisig_role = host
            .query(FindRolesByAccountId::new(proposer))
            .filter_with(|role_id| role_id.eq(multisig_role))
            .execute_single()
            .is_ok();
        let has_not_longer_ttl = {
            let Some(account_default_ttl_ms) = host
                .query_single(FindAccountMetadata::new(
                    multisig_account.clone(),
                    TRANSACTION_TTL_MS.parse().unwrap(),
                ))
                .ok()
                .and_then(|json| json.try_into_any::<u64>().ok())
            else {
                deny!(executor, "multisig account not found");
            };
            self.transaction_ttl_ms
                .map(u64::from)
                .map_or(true, |override_ttl_ms| {
                    override_ttl_ms <= account_default_ttl_ms
                })
        };

        if !(is_downward_proposal || has_not_longer_ttl) {
            deny!(executor, "ttl violates the restriction");
        };

        if !(is_downward_proposal || has_multisig_role) {
            deny!(executor, "not qualified to propose multisig");
        };

        if host
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                approvals_key(&instructions_hash),
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
        let now_ms: u64 = executor
            .context()
            .curr_block
            .creation_time()
            .as_millis()
            .try_into()
            .dbg_expect("shouldn't overflow within 584942417 years");
        let expires_at_ms: u64 = {
            let ttl_ms = self.transaction_ttl_ms.map(u64::from).unwrap_or_else(|| {
                executor
                    .host()
                    .query_single(FindAccountMetadata::new(
                        multisig_account.clone(),
                        TRANSACTION_TTL_MS.parse().unwrap(),
                    ))
                    .dbg_unwrap()
                    .try_into_any()
                    .dbg_unwrap()
            });
            now_ms.saturating_add(ttl_ms)
        };
        let approvals = BTreeSet::from([proposer]);
        let signatories: BTreeMap<AccountId, u8> = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                SIGNATORIES.parse().unwrap(),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();

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
                        self.transaction_ttl_ms,
                    )
                };
                propose_to_approve_me.visit_execute(executor);
            }
        }

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            instructions_key(&instructions_hash).clone(),
            Json::new(&self.instructions),
        )));

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            proposed_at_ms_key(&instructions_hash).clone(),
            Json::new(now_ms),
        )));

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            expires_at_ms_key(&instructions_hash).clone(),
            Json::new(expires_at_ms),
        )));

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account,
            approvals_key(&instructions_hash).clone(),
            Json::new(&approvals),
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
                approvals_key(&instructions_hash),
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

        let Some(instructions) = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                instructions_key(&instructions_hash),
            ))
            .ok()
            .and_then(|json| json.try_into_any::<Vec<InstructionBox>>().ok())
        else {
            // TODO Notify that the proposal has expired, while returning Ok for the entry deletion to take effect
            return Ok(());
        };
        let mut approvals: BTreeSet<AccountId> = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                approvals_key(&instructions_hash),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();

        approvals.insert(approver);

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            approvals_key(&instructions_hash),
            Json::new(&approvals),
        )));

        let signatories: BTreeMap<AccountId, u8> = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                SIGNATORIES.parse().unwrap(),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();
        let quorum: u16 = executor
            .host()
            .query_single(FindAccountMetadata::new(
                multisig_account.clone(),
                QUORUM.parse().unwrap(),
            ))
            .dbg_unwrap()
            .try_into_any()
            .dbg_unwrap();

        let is_authenticated = quorum
            <= signatories
                .into_iter()
                .filter(|(id, _)| approvals.contains(id))
                .map(|(_, weight)| u16::from(weight))
                .sum();

        if is_authenticated {
            for instruction in instructions {
                visit_seq!(executor.visit_instruction(&instruction));
            }

            // Cleanup the transaction entry
            visit_seq!(
                executor.visit_remove_account_key_value(&RemoveKeyValue::account(
                    multisig_account.clone(),
                    approvals_key(&instructions_hash),
                ))
            );
            visit_seq!(
                executor.visit_remove_account_key_value(&RemoveKeyValue::account(
                    multisig_account.clone(),
                    expires_at_ms_key(&instructions_hash),
                ))
            );
            visit_seq!(
                executor.visit_remove_account_key_value(&RemoveKeyValue::account(
                    multisig_account.clone(),
                    proposed_at_ms_key(&instructions_hash),
                ))
            );
            visit_seq!(
                executor.visit_remove_account_key_value(&RemoveKeyValue::account(
                    multisig_account.clone(),
                    instructions_key(&instructions_hash),
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
    let Some(expires_at_ms) = executor
        .host()
        .query_single(FindAccountMetadata::new(
            multisig_account.clone(),
            expires_at_ms_key(&instructions_hash),
        ))
        .ok()
        .and_then(|json| json.try_into_any::<u64>().ok())
    else {
        // Removed by another path
        return Ok(());
    };
    // Confirm expiration
    let now_ms: u64 = executor
        .context()
        .curr_block
        .creation_time()
        .as_millis()
        .try_into()
        .dbg_expect("shouldn't overflow within 584942417 years");
    if now_ms < expires_at_ms {
        return Ok(());
    }
    // Recurse through approvals
    let instructions: Vec<InstructionBox> = executor
        .host()
        .query_single(FindAccountMetadata::new(
            multisig_account.clone(),
            instructions_key(&instructions_hash),
        ))
        .dbg_unwrap()
        .try_into_any()
        .dbg_unwrap();
    for instruction in instructions {
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
            multisig_account.clone(),
            approvals_key(&instructions_hash),
        ))
    );
    visit_seq!(
        executor.visit_remove_account_key_value(&RemoveKeyValue::account(
            multisig_account.clone(),
            expires_at_ms_key(&instructions_hash),
        ))
    );
    visit_seq!(
        executor.visit_remove_account_key_value(&RemoveKeyValue::account(
            multisig_account.clone(),
            proposed_at_ms_key(&instructions_hash),
        ))
    );
    visit_seq!(
        executor.visit_remove_account_key_value(&RemoveKeyValue::account(
            multisig_account,
            instructions_key(&instructions_hash),
        ))
    );

    Ok(())
}
