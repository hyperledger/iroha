/// Cross-scope delegation negatives carried over from the retired Rust executor SDK suite.
mod cross_scope_permission_tests {
    use super::*;
    use iroha_data_model::nexus::UniversalAccountId;
    use iroha_executor_data_model::permission::account::AccountAliasPermissionScope;

    #[test]
    fn scoped_delegation_never_widens_to_a_sibling_scope() {
        let sponsor = checked_account_id();
        let other_sponsor = checked_account_id();
        let holder = checked_account_id();
        let subject = checked_account_id();
        let dataspace = DataSpaceId::new(10);
        let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL domain");
        let uaid = |seed: &[u8]| UniversalAccountId::from_hash(Hash::new(seed));
        let program = |sponsor: &AccountId| {
            FeeSponsorProgramId::new(sponsor.clone(), "retail".parse().expect("program name"))
        };
        let held: BTreeSet<Permission> = BTreeSet::from([
            executor_permission::nexus::CanManageFeeSponsorProgram {
                sponsor: sponsor.clone(),
            }
            .into(),
            executor_permission::nexus::CanPublishSpaceDirectoryManifestForUaid {
                dataspace,
                uaid: uaid(b"uaid::hbl-customer"),
            }
            .into(),
            executor_permission::nexus::CanPublishSpaceDirectoryManifestForAccountDomain {
                dataspace,
                domain: hbl.clone(),
            }
            .into(),
            executor_permission::query::CanReadAccountData {
                account: subject.clone(),
            }
            .into(),
        ]);
        let mut world = World::with(
            [],
            [
                Account::new(sponsor.clone()).build(&sponsor),
                Account::new(other_sponsor.clone()).build(&other_sponsor),
                Account::new(holder.clone()).build(&holder),
                Account::new(subject.clone()).build(&subject),
            ],
            [],
        );
        world.account_permissions.insert(holder.clone(), held);
        let state = state_for_testing(world);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let state_transaction = block.transaction();
        let allowed = |authority: &AccountId, permission: Permission| {
            initial_permission_delegation_allowed(&state_transaction, authority, &permission)
                .expect("delegation decision")
        };

        // Fee-sponsor enrollment follows the exact sponsor of the held manager token.
        assert!(allowed(
            &holder,
            executor_permission::nexus::CanEnrollFeeSponsorProgram {
                program_id: program(&sponsor),
            }
            .into(),
        ));
        assert!(!allowed(
            &holder,
            executor_permission::nexus::CanEnrollFeeSponsorProgram {
                program_id: program(&other_sponsor),
            }
            .into(),
        ));
        // Space-directory leaves propagate only their exact UAID or account domain.
        assert!(!allowed(
            &holder,
            executor_permission::nexus::CanPublishSpaceDirectoryManifestForUaid {
                dataspace,
                uaid: uaid(b"uaid::ubl-customer"),
            }
            .into(),
        ));
        assert!(!allowed(
            &holder,
            executor_permission::nexus::CanPublishSpaceDirectoryManifestForAccountDomain {
                dataspace,
                domain: ubl,
            }
            .into(),
        ));
        // An exact account reader may use, but never propagate, the subject's grant.
        let read: Permission = executor_permission::query::CanReadAccountData {
            account: subject.clone(),
        }
        .into();
        assert!(!allowed(&holder, read.clone()));
        assert!(allowed(&subject, read));
    }


    #[test]
    fn cross_dataspace_domain_permission_delegation_stays_exact() {
        let operator = checked_account_id();
        let holder = checked_account_id();
        let home = DomainId::try_new("retail", "home").unwrap();
        let target = DataSpaceId::UNIVERSAL;
        let leaf = |dataspace, domain| -> Permission {
            executor_permission::nexus::CanPublishSpaceDirectoryManifestForAccountDomain {
                dataspace,
                domain,
            }
            .into()
        };
        let exact = leaf(target, home.clone());
        let root: Permission =
            executor_permission::nexus::CanPublishSpaceDirectoryManifest { dataspace: target }
                .into();
        let mut world = World::with(
            [],
            [
                Account::new(operator.clone()).build(&operator),
                Account::new(holder.clone()).build(&holder),
            ],
            [],
        );
        world
            .account_permissions
            .insert(operator.clone(), BTreeSet::from([root.clone()]));
        world
            .account_permissions
            .insert(holder.clone(), BTreeSet::from([exact.clone()]));
        let state = state_for_testing(world);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let tx = block.transaction();
        let allowed = |authority: &AccountId, permission: Permission| {
            initial_permission_delegation_allowed(&tx, authority, &permission).unwrap()
        };
        assert!(
            allowed(&operator, exact.clone()),
            "target operator may issue scoped leaf"
        );
        assert!(
            allowed(&holder, exact),
            "existing exact-token redelegation remains allowed"
        );
        assert!(!allowed(
            &holder,
            leaf(target, DomainId::try_new("other", "home").unwrap())
        ));
        assert!(!allowed(
            &holder,
            leaf(target, DomainId::try_new("retail", "other").unwrap())
        ));
        let other_target = leaf(DataSpaceId::new(7), home);
        assert!(
            !allowed(&holder, other_target.clone()),
            "holder cannot widen target"
        );
        assert!(
            !allowed(&operator, other_target),
            "DS0 root cannot issue another target's leaf"
        );
        assert!(!allowed(&holder, root), "leaf cannot derive wide root");
        assert!(
            !allowed(
                &holder,
                executor_permission::nexus::CanPublishSpaceDirectoryManifestForUaid {
                    dataspace: target,
                    uaid: UniversalAccountId::from_hash(Hash::new(b"unrelated-uaid")),
                }
                .into()
            ),
            "domain leaf cannot derive per-UAID authority"
        );
    }

    #[test]
    fn alias_selector_and_manifest_delegation_stay_exact() {
        let owner = checked_account_id();
        let holder = checked_account_id();
        let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
        let ubl = DomainId::try_new("ubl", "sbp").expect("UBL domain");
        let dataspace = DataSpaceId::new(10);
        let delegated_scope = AccountAliasPermissionScope::Domain(hbl.clone());
        let resolve = |scope: AccountAliasPermissionScope| -> Permission {
            executor_permission::account::CanResolveAccountAlias { scope }.into()
        };
        let delegation: Permission =
            executor_permission::account::CanDelegateAccountAliasResolution {
                scope: delegated_scope.clone(),
            }
            .into();
        let contract = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &owner,
            88,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let noncanonical_selectors: Vec<Permission> = [" main", ""]
            .into_iter()
            .map(|entrypoint| {
                executor_permission::smart_contract::CanInvokeContractEntrypoint {
                    contract: contract.clone(),
                    entrypoint: entrypoint.to_owned(),
                }
                .into()
            })
            .collect();
        let unscoped_manifest_root = Permission::new(
            "CanPublishSpaceDirectoryManifest".to_owned(),
            Json::from_raw_json("null".to_owned()).expect("valid JSON fixture"),
        );
        let mut world = World::with(
            [
                Domain::new(hbl).build(&owner),
                Domain::new(ubl.clone()).build(&owner),
            ],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(holder.clone()).build(&holder),
            ],
            [],
        );
        world.account_permissions.insert(
            holder.clone(),
            noncanonical_selectors
                .iter()
                .cloned()
                .chain([delegation.clone(), unscoped_manifest_root])
                .collect(),
        );
        let state = state_for_testing(world);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let state_transaction = block.transaction();
        let allowed = |permission: Permission| {
            initial_permission_delegation_allowed(&state_transaction, &holder, &permission)
        };

        // A domain-scoped alias-resolution delegate grants resolution for exactly that domain
        // and may pass the delegation on, but never a sibling domain or a dataspace scope.
        assert!(allowed(resolve(delegated_scope)).expect("exact resolution delegation"));
        assert!(allowed(delegation).expect("delegation token propagation"));
        assert!(!allowed(resolve(AccountAliasPermissionScope::Domain(ubl))).expect("sibling"));
        assert!(
            !allowed(resolve(AccountAliasPermissionScope::Dataspace(dataspace)))
                .expect("dataspace scope")
        );
        // Holding a malformed selector never lets its holder copy it.
        for selector in noncanonical_selectors {
            assert!(matches!(
                allowed(selector).map_err(crate::execution_attempt::expect_completed_rejection),
                Err(ValidationFail::NotPermitted(_))
            ));
        }
        // An unscoped manifest root does not authorize the scoped dataspace root.
        assert!(
            !allowed(
                executor_permission::nexus::CanPublishSpaceDirectoryManifest { dataspace }.into()
            )
            .expect("scoped manifest root")
        );
    }
}
