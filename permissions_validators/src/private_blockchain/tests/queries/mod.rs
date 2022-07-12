use super::*;

mod account;
mod asset;
mod domain;
mod role;
mod transaction;
mod trigger;

mod peer {
    use super::*;

    #[test]
    fn find_all_peers() {
        let TestEnv {
            alice_id,
            bob_id,
            carol_id,
            wsv,
            ..
        } = TestEnv::new();

        let find_all_peers = QueryBox::FindAllPeers(FindAllPeers::new());

        {
            let only_accounts_domain = query::OnlyAccountsDomain;

            // Always allow do it for any account.
            assert!(only_accounts_domain
                .check(&alice_id, &find_all_peers, &wsv)
                .is_allow());
            assert!(only_accounts_domain
                .check(&bob_id, &find_all_peers, &wsv)
                .is_allow());
            assert!(only_accounts_domain
                .check(&carol_id, &find_all_peers, &wsv)
                .is_allow());
        }

        {
            let only_accounts_data = query::OnlyAccountsData;

            // Always returns an error for any account.
            assert!(only_accounts_data
                .check(&alice_id, &find_all_peers, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&bob_id, &find_all_peers, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&carol_id, &find_all_peers, &wsv)
                .is_deny());
        }
    }
}

mod block {
    use super::*;

    #[test]
    fn find_all_blocks() {
        let TestEnv {
            alice_id,
            bob_id,
            carol_id,
            wsv,
            ..
        } = TestEnv::new();

        let find_all_blocks = QueryBox::FindAllBlocks(FindAllBlocks::new());

        {
            let only_accounts_domain = query::OnlyAccountsDomain;

            // Always returns an error for any account.
            assert!(only_accounts_domain
                .check(&alice_id, &find_all_blocks, &wsv)
                .is_deny());
            assert!(only_accounts_domain
                .check(&bob_id, &find_all_blocks, &wsv)
                .is_deny());
            assert!(only_accounts_domain
                .check(&carol_id, &find_all_blocks, &wsv)
                .is_deny());
        }

        {
            let only_accounts_data = query::OnlyAccountsData;

            // Always returns an error for any account.
            assert!(only_accounts_data
                .check(&alice_id, &find_all_blocks, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&bob_id, &find_all_blocks, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&carol_id, &find_all_blocks, &wsv)
                .is_deny());
        }
    }
}

mod permission {
    use super::*;

    #[test]
    fn find_permission_tokens_by_account_id() {
        let TestEnv {
            alice_id,
            bob_id,
            carol_id,
            wsv,
            ..
        } = TestEnv::new();

        let find_alice_permission_tokens =
            QueryBox::FindPermissionTokensByAccountId(FindPermissionTokensByAccountId {
                id: alice_id.clone().into(),
            });
        let find_bob_permission_tokens =
            QueryBox::FindPermissionTokensByAccountId(FindPermissionTokensByAccountId {
                id: bob_id.clone().into(),
            });
        let find_carol_permission_tokens =
            QueryBox::FindPermissionTokensByAccountId(FindPermissionTokensByAccountId {
                id: carol_id.clone().into(),
            });

        {
            let only_accounts_domain = query::OnlyAccountsDomain;

            assert!(only_accounts_domain
                .check(&alice_id, &find_alice_permission_tokens, &wsv)
                .is_allow());
            assert!(only_accounts_domain
                .check(&alice_id, &find_carol_permission_tokens, &wsv)
                .is_deny());
            assert!(only_accounts_domain
                .check(&bob_id, &find_alice_permission_tokens, &wsv)
                .is_allow());
            assert!(only_accounts_domain
                .check(&bob_id, &find_bob_permission_tokens, &wsv)
                .is_allow());
            assert!(only_accounts_domain
                .check(&carol_id, &find_alice_permission_tokens, &wsv)
                .is_deny());
            assert!(only_accounts_domain
                .check(&carol_id, &find_carol_permission_tokens, &wsv)
                .is_allow());
        }

        {
            let only_accounts_data = query::OnlyAccountsData;

            assert!(only_accounts_data
                .check(&alice_id, &find_alice_permission_tokens, &wsv)
                .is_allow());
            assert!(only_accounts_data
                .check(&alice_id, &find_carol_permission_tokens, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&bob_id, &find_alice_permission_tokens, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&bob_id, &find_bob_permission_tokens, &wsv)
                .is_allow());
            assert!(only_accounts_data
                .check(&carol_id, &find_alice_permission_tokens, &wsv)
                .is_deny());
            assert!(only_accounts_data
                .check(&carol_id, &find_carol_permission_tokens, &wsv)
                .is_allow());
        }
    }
}
