//! Signed genesis role custody, genuine paid removal and exact certified restart.

use super::*;
use iroha_data_model::{
    ValidationFail,
    permission::Permission,
    role::Role,
    transaction::{TransactionDomain, error::TransactionRejectionReason},
};
use iroha_executor_data_model::permission::{query::CanReadAllLedgerData, role::CanManageRoles};

fn reader_role() -> iroha_data_model::role::RoleId {
    "bank_service_read".parse().unwrap()
}
fn admin_role() -> iroha_data_model::role::RoleId {
    "bank_role_admin".parse().unwrap()
}
fn unrelated_role() -> iroha_data_model::role::RoleId {
    "unrelated_bank_role".parse().unwrap()
}
fn role_config(global: &CertifiedTestChain, ds: DataSpaceId) -> TestChainConfig {
    let mut config = private_config(global, ds);
    let admin = if ds == FIRST {
        account(&payer())
    } else {
        account(&config.genesis_key)
    };
    config.genesis_instructions.extend([
        Register::role(
            Role::new(reader_role(), account(&receiver())).add_permission(CanReadAllLedgerData),
        )
        .into(),
        Register::role(Role::new(admin_role(), admin).add_permission(CanManageRoles)).into(),
        Register::role(Role::new(unrelated_role(), account(&receiver()))).into(),
    ]);
    config
}
#[inline(never)]
fn role_roots() -> Roots {
    let mut global = CertifiedTestChain::start(paid_global_config()).unwrap();
    let h2 = paid_global_sign(
        &global,
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "authenticate parent before signed read-role genesis".into(),
        )
        .into()],
        1_499,
    );
    assert_eq!(global.commit_at(1_500, vec![h2]), vec![true]);
    let participants =
        [FIRST, SECOND].map(|ds| CertifiedTestChain::start(role_config(&global, ds)).unwrap());
    Roots {
        global,
        participants,
    }
}
fn effective(chain: &CertifiedTestChain, account: &AccountId, target: Permission) -> bool {
    let view = chain.state().view();
    view.world()
        .account_permissions_iter(account)
        .unwrap()
        .any(|value| value == &target)
        || view.world().account_roles_iter(account).any(|id| {
            view.world()
                .roles()
                .get(id)
                .is_some_and(|role| role.permissions().any(|value| value == &target))
        })
}
fn assert_debit(
    chain: &CertifiedTestChain,
    approval: &iroha_data_model::sumeragi_amx::AmxDebitApprovalV1,
) {
    let view = chain.state().view();
    assert!(
        view.world()
            .account_permissions_iter(&account(&receiver()))
            .unwrap()
            .any(|permission| approval.matches_permission(permission).unwrap())
    );
    assert_eq!(
        balance(chain, FIRST, principal(), account(&payer())),
        Quantity::from(1_000_u32)
    );
    assert!(native(chain).escrows.is_empty());
}
fn commit(
    chain: &mut CertifiedTestChain,
    signer: &KeyPair,
    instruction: InstructionBox,
    at: u64,
    expected: Result<(), &str>,
) {
    let carrier = chain.sign(signer, [instruction], at - 1);
    let outcomes = chain.commit_at(at, vec![carrier]);
    assert_eq!(
        outcomes,
        vec![expected.is_ok()],
        "genuine role operation: {:?}",
        chain
            .committed(chain.height())
            .block()
            .network_output_at(0)
            .map(|(_, output)| &output.result)
    );
    let committed = chain.committed(chain.height());
    let result = &committed
        .block()
        .network_output_at(0)
        .expect("original role carrier must have its committed output")
        .1
        .result
        .0;
    match expected {
        Ok(()) => assert!(result.is_ok(), "successful role operation: {result:?}"),
        Err(expected_reason) => assert!(
            matches!(
                result,
                Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason)))
                    if reason == expected_reason
            ),
            "role rejection must be the exact intended authorization refusal {expected_reason:?}; got {result:?}"
        ),
    }
}

#[test]
fn native_private_read_role_removal_preserves_debit_and_survives_certified_restart() {
    let mut roots = role_roots();
    let transaction = roots.transaction(100, 0xE1);
    let approval = roots.approval(0, &transaction);
    roots.approve(0, &transaction, account(&receiver()), 2_500);
    assert!(effective(
        &roots.participants[0],
        &account(&receiver()),
        CanReadAllLedgerData.into()
    ));
    assert!(effective(
        &roots.participants[0],
        &account(&payer()),
        CanManageRoles.into()
    ));
    let chain = &mut roots.participants[0];
    let carrier = chain.sign(&payer(), [Unregister::role(reader_role()).into()], 2_999);
    let outcomes = chain.commit_at(3_000, vec![carrier]);
    assert_eq!(
        outcomes,
        vec![true],
        "bank management must delete its dedicated read role through ordinary native authorization: {:?}",
        chain
            .committed(chain.height())
            .block()
            .network_output_at(0)
            .map(|(_, output)| &output.result)
    );
    assert!(!effective(
        chain,
        &account(&receiver()),
        CanReadAllLedgerData.into()
    ));
    assert_debit(chain, &approval);
    assert!(
        chain
            .state()
            .view()
            .world()
            .roles()
            .get(&unrelated_role())
            .is_some()
    );
    assert!(
        effective(
            &roots.participants[1],
            &account(&receiver()),
            CanReadAllLedgerData.into()
        ),
        "the identical textual role name in another signed root is untouched"
    );
    let mut restarted = CertifiedTestChain::start(role_config(&roots.global, FIRST)).unwrap();
    restarted.replay_from(&roots.participants[0]).unwrap();
    assert_eq!(restarted.height(), roots.participants[0].height());
    assert!(!effective(
        &restarted,
        &account(&receiver()),
        CanReadAllLedgerData.into()
    ));
    assert_debit(&restarted, &approval);
    // Administrative authority is role-derived too; self-removal must not leave
    // a cached management capability authorizing the next paid transaction.
    commit(
        &mut restarted,
        &payer(),
        Unregister::role(admin_role()).into(),
        3_100,
        Ok(()),
    );
    assert!(!effective(
        &restarted,
        &account(&payer()),
        CanManageRoles.into()
    ));
    commit(
        &mut restarted,
        &payer(),
        Unregister::role(unrelated_role()).into(),
        3_200,
        Err("Can't unregister role"),
    );
    assert!(
        restarted
            .state()
            .view()
            .world()
            .roles()
            .get(&unrelated_role())
            .is_some()
    );
    assert_debit(&restarted, &approval);
}

#[test]
fn native_private_read_role_cannot_be_removed_by_reader_or_foreign_bank_manager() {
    let mut roots = role_roots();
    commit(
        &mut roots.participants[0],
        &receiver(),
        Unregister::role(reader_role()).into(),
        2_000,
        Err("Can't unregister role"),
    );
    assert!(effective(
        &roots.participants[0],
        &account(&receiver()),
        CanReadAllLedgerData.into()
    ));
    // The same canonical payer account exists in bank B but has no management role there.
    commit(
        &mut roots.participants[1],
        &payer(),
        Unregister::role(reader_role()).into(),
        2_000,
        Err("Can't unregister role"),
    );
    assert!(effective(
        &roots.participants[1],
        &account(&receiver()),
        CanReadAllLedgerData.into()
    ));
    let original =
        roots.participants[0].sign(&payer(), [Unregister::role(reader_role()).into()], 2_099);
    let view = roots.participants[1].state().view();
    let (_, clock) = TimeSource::new_mock(Duration::from_millis(2_100));
    let bank_a_network = roots.participants[0].network_id();
    let bank_b_network = roots.participants[1].network_id();
    assert_ne!(bank_a_network, bank_b_network);
    let rejection = match AcceptedTransaction::accept_with_time_source(
        original,
        &bank_b_network,
        Duration::from_secs(1),
        view.world().parameters().transaction(),
        &view.crypto(),
        &clock,
    ) {
        Ok(_) => panic!(
            "a correctly signed bank-A deletion cannot cross the signed bank-B network domain"
        ),
        Err(error) => error,
    };
    match rejection {
        crate::tx::AcceptTransactionFail::TransactionDomainMismatch(mismatch) => {
            assert_eq!(
                mismatch.expected,
                TransactionDomain::Network(bank_b_network)
            );
            assert_eq!(mismatch.actual, TransactionDomain::Network(bank_a_network));
        }
        other => {
            panic!("bank-A deletion must fail for its exact signed network domain, got {other:?}")
        }
    }
    drop(view);
    // Existing genesis-only policy still forbids moving or reissuing the read capability.
    commit(
        &mut roots.participants[0],
        &payer(),
        Grant::account_role(reader_role(), account(&payer())).into(),
        2_200,
        Err("instruction has no reviewed private-root scope owner"),
    );
    commit(
        &mut roots.participants[0],
        &payer(),
        Register::role(
            Role::new("replacement_read".parse().unwrap(), account(&receiver()))
                .add_permission(CanReadAllLedgerData),
        )
        .into(),
        2_300,
        Err("instruction has no reviewed private-root scope owner"),
    );
    assert!(effective(
        &roots.participants[0],
        &account(&receiver()),
        CanReadAllLedgerData.into()
    ));
}
