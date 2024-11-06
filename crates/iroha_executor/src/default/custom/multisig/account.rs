//! Validation and execution logic of instructions for multisig accounts

use super::*;

impl VisitExecute for MultisigRegister {
    fn visit<V: Execute + Visit + ?Sized>(&self, executor: &mut V) {
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
        let host = executor.host();
        let registrant = executor.context().authority.clone();
        let multisig_role = multisig_role_for(&self.account);
        let multisig_account = {
            let metadata = [
                (SIGNATORIES.parse().unwrap(), Json::new(&self.signatories)),
                (QUORUM.parse().unwrap(), Json::new(self.quorum)),
                (
                    TRANSACTION_TTL_MS.parse().unwrap(),
                    Json::new(self.transaction_ttl_ms),
                ),
            ]
            .into_iter()
            .fold(Metadata::default(), |mut acc, (k, v)| {
                acc.insert(k, v).unwrap();
                acc
            });
            Account::new(self.account.clone()).with_metadata(metadata)
        };

        host.submit(&Register::account(multisig_account))
            .dbg_expect("registrant should successfully register a multisig account");

        host.submit(&Register::role(
            // Temporarily grant a multisig role to the registrant to delegate the role to the signatories
            Role::new(multisig_role.clone(), registrant.clone()),
        ))
        .dbg_expect("registrant should successfully register a multisig role");

        for signatory in self.signatories.keys().cloned() {
            host.submit(&Grant::account_role(multisig_role.clone(), signatory))
                .dbg_expect(
                    "registrant should successfully grant the multisig role to signatories",
                );
        }

        // FIXME No roles to revoke found, which should have been granted to the registrant
        // host.submit(&Revoke::account_role(multisig_role, registrant))
        //     .dbg_expect(
        //         "registrant should successfully revoke the multisig role from the registrant",
        //     );

        Ok(())
    }
}
