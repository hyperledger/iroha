//! Validation and execution logic of instructions for multisig accounts

use super::*;

impl VisitExecute for MultisigRegister {
    fn visit(&self, executor: &mut Executor) {
        let host = executor.host();
        let target_domain = self.account.domain();

        // Any account in a domain can register any multisig account in the domain
        // TODO Restrict access to the multisig signatories?
        // TODO Impose proposal and approval process?
        if target_domain != executor.context().authority.domain() {
            deny!(
                executor,
                "multisig account and its registrant must be in the same domain"
            )
        }

        let Ok(domain_found) = host
            .query(FindDomains)
            .filter_with(|domain| domain.id.eq(target_domain.clone()))
            .execute_single()
        else {
            deny!(
                executor,
                "domain must exist before registering multisig account"
            );
        };

        for signatory in self.signatories.keys().cloned() {
            let Ok(_signatory_found) = host
                .query(FindAccounts)
                .filter_with(|account| account.id.eq(signatory))
                .execute_single()
            else {
                deny!(
                    executor,
                    "signatories must exist before registering multisig account"
                );
            };
        }

        // Pass validation and elevate to the domain owner authority
        executor.context_mut().authority = domain_found.owned_by().clone();
    }

    fn execute(
        self,
        executor: &mut Executor,
        _init_authority: &AccountId,
    ) -> Result<(), ValidationFail> {
        let host = executor.host();
        let domain_owner = executor.context().authority.clone();
        let multisig_account = self.account;
        let multisig_role = multisig_role_for(&multisig_account);

        host.submit(&Register::account(Account::new(multisig_account.clone())))
            .dbg_expect("domain owner should successfully register a multisig account");

        host.submit(&SetKeyValue::account(
            multisig_account.clone(),
            SIGNATORIES.parse().unwrap(),
            Json::new(&self.signatories),
        ))
        .dbg_unwrap();

        host.submit(&SetKeyValue::account(
            multisig_account.clone(),
            QUORUM.parse().unwrap(),
            Json::new(&self.quorum),
        ))
        .dbg_unwrap();

        host.submit(&SetKeyValue::account(
            multisig_account.clone(),
            TRANSACTION_TTL_MS.parse().unwrap(),
            Json::new(&self.transaction_ttl_ms),
        ))
        .dbg_unwrap();

        host.submit(&Register::role(
            // Temporarily grant a multisig role to the domain owner to delegate the role to the signatories
            Role::new(multisig_role.clone(), domain_owner.clone()),
        ))
        .dbg_expect("domain owner should successfully register a multisig role");

        for signatory in self.signatories.keys().cloned() {
            host.submit(&Grant::account_role(multisig_role.clone(), signatory))
                .dbg_expect(
                    "domain owner should successfully grant the multisig role to signatories",
                );
        }

        // FIXME No roles to revoke found, which should have been granted to the domain owner
        // host.submit(&Revoke::account_role(multisig_role, domain_owner))
        //     .dbg_expect(
        //         "domain owner should successfully revoke the multisig role from the domain owner",
        //     );

        Ok(())
    }
}
