//! Validation and execution logic of instructions for multisig accounts

use iroha_executor_data_model::permission::account::CanRegisterAccount;

use super::*;
use crate::permission::domain::is_domain_owner;

impl VisitExecute for MultisigRegister {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
        let registrant = executor.context().authority.clone();
        let target_domain = self.account.domain();
        let host = executor.host();

        let Ok(is_domain_owner) = is_domain_owner(target_domain, &registrant, host) else {
            deny!(
                executor,
                "domain must exist before registering multisig account"
            );
        };

        let has_permission = {
            CanRegisterAccount {
                domain: target_domain.clone(),
            }
            .is_owned_by(&registrant, host)
        };

        // Impose the same restriction as for personal account registrations
        // TODO Allow the signatories to register the multisig account? With propose and approve procedures?
        if !(is_domain_owner || has_permission) {
            deny!(
                executor,
                "registrant must have sufficient permission to register an account"
            );
        }

        for signatory in self.signatories.keys().cloned() {
            if host
                .query(FindAccounts)
                .filter_with(|account| account.id.eq(signatory))
                .execute_single()
                .is_err()
            {
                deny!(
                    executor,
                    "signatories must exist before registering multisig account"
                );
            }
        }
    }

    fn execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) -> Result<(), ValidationFail> {
        let domain_owner = executor
            .host()
            .query(FindDomains)
            .filter_with(|domain| domain.id.eq(self.account.domain().clone()))
            .execute_single()
            .dbg_unwrap()
            .owned_by()
            .clone();

        // Authorize as the domain owner:
        // Just having permission to register accounts is insufficient to register multisig roles
        executor.context_mut().authority = domain_owner.clone();

        let multisig_account = self.account;
        let multisig_role = multisig_role_for(&multisig_account);

        visit_seq!(executor
            .visit_register_account(&Register::account(Account::new(multisig_account.clone()))));

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            SIGNATORIES.parse().unwrap(),
            Json::new(&self.signatories),
        )));

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            QUORUM.parse().unwrap(),
            Json::new(self.quorum),
        )));

        visit_seq!(executor.visit_set_account_key_value(&SetKeyValue::account(
            multisig_account.clone(),
            TRANSACTION_TTL_MS.parse().unwrap(),
            Json::new(self.transaction_ttl_ms),
        )));

        visit_seq!(executor.visit_register_role(&Register::role(
            // Temporarily grant a multisig role to the domain owner to delegate the role to the signatories
            Role::new(multisig_role.clone(), domain_owner.clone()),
        )));

        for signatory in self.signatories.keys().cloned() {
            visit_seq!(executor
                .visit_grant_account_role(&Grant::account_role(multisig_role.clone(), signatory)));
        }

        visit_seq!(
            executor.visit_revoke_account_role(&Revoke::account_role(multisig_role, domain_owner))
        );

        Ok(())
    }
}
