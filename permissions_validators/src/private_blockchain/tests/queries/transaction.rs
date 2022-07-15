use super::*;

#[test]
fn find_all_transactions() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_all_transactions = QueryBox::FindAllTransactions(FindAllTransactions::new());

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        // Always returns an error for any account.
        assert!(only_accounts_domain
            .check(&alice_id, &find_all_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_all_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_all_transactions, &wsv)
            .is_deny());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        // Always returns an error for any account.
        assert!(only_accounts_data
            .check(&alice_id, &find_all_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_all_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_all_transactions, &wsv)
            .is_deny());
    }
}

#[test]
fn find_transactions_by_account_id() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_alice_transactions =
        QueryBox::FindTransactionsByAccountId(FindTransactionsByAccountId::new(alice_id.clone()));
    let find_bob_transactions =
        QueryBox::FindTransactionsByAccountId(FindTransactionsByAccountId::new(bob_id.clone()));
    let find_carol_transactions =
        QueryBox::FindTransactionsByAccountId(FindTransactionsByAccountId::new(carol_id.clone()));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        assert!(only_accounts_domain
            .check(&alice_id, &find_alice_transactions, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&alice_id, &find_carol_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&bob_id, &find_alice_transactions, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_bob_transactions, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_alice_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_domain
            .check(&carol_id, &find_carol_transactions, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        assert!(only_accounts_data
            .check(&alice_id, &find_alice_transactions, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&alice_id, &find_carol_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_alice_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&bob_id, &find_bob_transactions, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&carol_id, &find_alice_transactions, &wsv)
            .is_deny());
        assert!(only_accounts_data
            .check(&carol_id, &find_carol_transactions, &wsv)
            .is_allow());
    }
}

#[test]
fn find_transaction_by_hash() {
    let TestEnv {
        alice_id,
        bob_id,
        carol_id,
        wsv,
        ..
    } = TestEnv::new();

    let find_alice_transaction =
        QueryBox::FindTransactionByHash(FindTransactionByHash::new(Hash::new(&[])));

    {
        let only_accounts_domain = query::OnlyAccountsDomain;

        // Always allow for any account.
        assert!(only_accounts_domain
            .check(&alice_id, &find_alice_transaction, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&bob_id, &find_alice_transaction, &wsv)
            .is_allow());
        assert!(only_accounts_domain
            .check(&carol_id, &find_alice_transaction, &wsv)
            .is_allow());
    }

    {
        let only_accounts_data = query::OnlyAccountsData;

        // Always allow for any account.
        assert!(only_accounts_data
            .check(&alice_id, &find_alice_transaction, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&bob_id, &find_alice_transaction, &wsv)
            .is_allow());
        assert!(only_accounts_data
            .check(&carol_id, &find_alice_transaction, &wsv)
            .is_allow());
    }
}
