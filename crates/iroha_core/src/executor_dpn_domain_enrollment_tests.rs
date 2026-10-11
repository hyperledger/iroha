/// Exact-domain DPN enrollment authorization and observation boundaries.
mod dpn_domain_enrollment_tests {
    use super::*;
    use iroha_data_model::{
        account::{
            AccountAddress,
            rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
        },
        nexus::{DataSpaceCatalog, UniversalAccountId},
        sns::{NameControllerV1, NameRecordV1, NameStatus},
    };
    use iroha_executor_data_model::permission::dpn::{
        CanGrantDpnUserForAccountDomain, DpnAdmin, DpnUser,
    };

    struct Fixture {
        world: World,
        admin: AccountId,
        registrar: AccountId,
        customer: AccountId,
        domain: DomainId,
        alias: AccountAlias,
        uaid: UniversalAccountId,
    }
    fn fixture() -> Fixture {
        let admin = checked_account_id();
        let registrar = checked_account_id();
        let customer = checked_account_id();
        let domain = DomainId::try_new("nevo", "universal").unwrap();
        let uaid = UniversalAccountId::from_hash(Hash::new(b"dpn-enrollment-fixture"));
        let mut world = World::with(
            [Domain::new(domain.clone()).build(&admin)],
            [
                Account::new(admin.clone()).build(&admin),
                Account::new(registrar.clone()).build(&registrar),
                Account::new(customer.clone())
                    .with_uaid(Some(uaid))
                    .build(&customer),
            ],
            [],
        );
        world.uaid_accounts.insert(uaid, customer.clone());
        world
            .account_permissions
            .insert(admin.clone(), BTreeSet::from([DpnAdmin.into()]));
        world.account_permissions.insert(
            registrar.clone(),
            BTreeSet::from([CanGrantDpnUserForAccountDomain {
                domain: domain.clone(),
            }
            .into()]),
        );
        let alias = AccountAlias::new(
            "customer".parse().unwrap(),
            Some(AccountAliasDomain::new("nevo".parse().unwrap())),
            DataSpaceId::UNIVERSAL,
        );
        world
            .account_aliases
            .insert(alias.clone(), customer.clone());
        world
            .account_aliases_by_account
            .insert(customer.clone(), BTreeSet::from([alias.clone()]));
        world.replace_account_rekey_record_for_testing(AccountRekeyRecord::new(
            alias.clone(),
            customer.clone(),
        ));
        for (selector, owner) in [
            (
                crate::sns::selector_for_account_alias(&alias, &DataSpaceCatalog::default())
                    .unwrap(),
                &customer,
            ),
            (crate::sns::selector_for_domain(&domain).unwrap(), &admin),
        ] {
            let address = AccountAddress::from_account_id(owner).unwrap();
            let lease = NameRecordV1::new(
                selector.clone(),
                owner.clone(),
                vec![NameControllerV1::account(&address)],
                0,
                0,
                100,
                200,
                300,
                Metadata::default(),
            );
            world
                .smart_contract_state_mut_for_testing()
                .insert(crate::sns::record_storage_key(&selector), lease.encode());
        }
        Fixture {
            world,
            admin,
            registrar,
            customer,
            domain,
            alias,
            uaid,
        }
    }
    fn permission_query(customer: &AccountId) -> QueryRequest {
        QueryRequest::Start(QueryWithParams {
            query: (),
            query_payload: data_model_query::permission::prelude::FindPermissionsByAccountId::new(
                customer.clone(),
            )
            .encode(),
            item: QueryItemKind::Permission,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: Default::default(),
        })
    }
    #[test]
    fn dpn_domain_enrollment_grants_only_exact_user_and_two_queries() {
        let f = fixture();
        let state = state_after_genesis(f.world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(state.view().latest_block_hash().unwrap()),
            None,
            50,
            0,
        ));
        let mut tx = block.transaction();
        let grant = Grant::account_permission(Permission::from(DpnUser), f.customer.clone());
        super::super::Executor::Initial
            .execute_instruction(&mut tx, &f.registrar, grant.into())
            .unwrap();
        let account_query = QueryRequest::Singular(
            data_model_query::account::prelude::FindAccountById::new(f.customer.clone()).into(),
        );
        for query in [account_query, permission_query(&f.customer)] {
            validate_builtin_native_query_permission(tx.world(), &f.registrar, &query, 50).unwrap();
            assert!(
                validate_builtin_native_query_permission(tx.world(), &f.registrar, &query, 101)
                    .is_err()
            );
        }
        for permission in [
            Permission::from(DpnAdmin),
            executor_permission::dpn::DpnInori.into(),
            executor_permission::dpn::DpnSettlement.into(),
            executor_permission::dpn::DpnEprGuard.into(),
            Permission::new("DpnUser".to_owned(), Json::new(5_u32)),
        ] {
            super::super::Executor::Initial
                .execute_instruction(
                    &mut tx,
                    &f.registrar,
                    Grant::account_permission(permission, f.customer.clone()).into(),
                )
                .expect_err("scoped enrollment cannot grant other roles or malformed DpnUser");
        }
        super::super::Executor::Initial
            .execute_instruction(
                &mut tx,
                &f.registrar,
                Revoke::account_permission(Permission::from(DpnUser), f.customer.clone()).into(),
            )
            .expect_err("grant capability is not revocation authority");
        let role_query = QueryRequest::Start(QueryWithParams {
            query: (),
            query_payload: data_model_query::role::prelude::FindRolesByAccountId::new(
                f.customer.clone(),
            )
            .encode(),
            item: QueryItemKind::RoleId,
            predicate_bytes: Vec::new(),
            selector_bytes: Vec::new(),
            params: Default::default(),
        });
        assert!(
            validate_builtin_native_query_permission(tx.world(), &f.registrar, &role_query, 50)
                .is_err()
        );
        let asset_id = AssetId::new(
            AssetDefinitionId::derive_from_components(f.domain, "coin".parse().unwrap()),
            f.customer,
        );
        let assets = QueryRequest::Singular(
            data_model_query::asset::prelude::FindAssetById::new(asset_id).into(),
        );
        assert!(
            validate_builtin_native_query_permission(tx.world(), &f.registrar, &assets, 50)
                .is_err()
        );
    }
    #[test]
    fn dpn_domain_enrollment_rejects_foreign_stale_and_unbound_accounts() {
        for failure in [
            "domain",
            "dataspace",
            "uaid",
            "uaid_index",
            "rebound",
            "expired",
            "suspended",
            "malformed",
        ] {
            let mut f = fixture();
            match failure {
                "domain" | "dataspace" => {
                    let domain = if failure == "domain" {
                        DomainId::try_new("other", "universal")
                    } else {
                        DomainId::try_new("nevo", "other")
                    }
                    .unwrap();
                    f.world.account_permissions.insert(
                        f.registrar.clone(),
                        BTreeSet::from([CanGrantDpnUserForAccountDomain { domain }.into()]),
                    );
                }
                "uaid" => {
                    f.world.accounts.insert(
                        f.customer.clone(),
                        iroha_data_model::account::AccountValue::new(
                            iroha_data_model::account::AccountDetails::default(),
                        ),
                    );
                }
                "uaid_index" => {
                    f.world.uaid_accounts.insert(f.uaid, f.admin.clone());
                }
                "rebound" => {
                    f.world
                        .account_aliases
                        .insert(f.alias.clone(), f.admin.clone());
                }
                "suspended" => {
                    let selector = crate::sns::selector_for_account_alias(
                        &f.alias,
                        &DataSpaceCatalog::default(),
                    )
                    .unwrap();
                    let key = crate::sns::record_storage_key(&selector);
                    let bytes = f
                        .world
                        .smart_contract_state_mut_for_testing()
                        .view()
                        .get(&key)
                        .unwrap()
                        .clone();
                    let mut record = NameRecordV1::decode(&mut bytes.as_slice()).unwrap();
                    record.status = NameStatus::Frozen(iroha_data_model::sns::NameFrozenStateV1 {
                        reason: "enrollment suspended".to_owned(),
                        until_ms: 100,
                    });
                    f.world
                        .smart_contract_state_mut_for_testing()
                        .insert(key, record.encode());
                }
                "malformed" => {
                    f.world.account_permissions.insert(
                        f.registrar.clone(),
                        BTreeSet::from([Permission::new(
                            "CanGrantDpnUserForAccountDomain".to_owned(),
                            Json::new(()),
                        )]),
                    );
                }
                _ => {}
            }
            let state = state_after_genesis(f.world);
            let now = if failure == "expired" { 101 } else { 50 };
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                Some(state.view().latest_block_hash().unwrap()),
                None,
                now,
                0,
            ));
            let mut tx = block.transaction();
            assert!(
                !authority_can_enroll_dpn_account(tx.world(), &f.registrar, &f.customer, now)
                    .unwrap_or(false),
                "{failure}"
            );
            super::super::Executor::Initial
                .execute_instruction(
                    &mut tx,
                    &f.registrar,
                    Grant::account_permission(Permission::from(DpnUser), f.customer.clone()).into(),
                )
                .expect_err(failure);
            assert!(
                validate_builtin_native_query_permission(
                    tx.world(),
                    &f.registrar,
                    &permission_query(&f.customer),
                    now
                )
                .is_err(),
                "{failure}"
            );
        }
    }
    #[test]
    fn dpn_domain_enrollment_capability_requires_direct_admin_and_live_domain_owner() {
        let f = fixture();
        let token: Permission = CanGrantDpnUserForAccountDomain {
            domain: f.domain.clone(),
        }
        .into();
        let state = state_after_genesis(f.world);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            Some(state.view().latest_block_hash().unwrap()),
            None,
            50,
            0,
        ));
        let mut tx = block.transaction();
        for authority in [&f.registrar, &f.customer] {
            assert!(!initial_permission_delegation_allowed(&tx, authority, &token).unwrap());
        }
        assert!(initial_permission_delegation_allowed(&tx, &f.admin, &token).unwrap());
        super::super::Executor::Initial
            .execute_instruction(
                &mut tx,
                &f.admin,
                Grant::account_permission(token.clone(), f.customer.clone()).into(),
            )
            .unwrap();
        super::super::Executor::Initial
            .execute_instruction(
                &mut tx,
                &f.admin,
                Revoke::account_permission(token.clone(), f.customer.clone()).into(),
            )
            .unwrap();
        tx.world
            .account_permissions
            .insert(f.customer.clone(), BTreeSet::from([DpnAdmin.into()]));
        assert!(
            !initial_permission_delegation_allowed(&tx, &f.customer, &token).unwrap(),
            "foreign admin does not own this domain"
        );
        tx.world.account_permissions.remove(f.admin.clone());
        assert!(
            !initial_permission_delegation_allowed(&tx, &f.admin, &token).unwrap(),
            "domain ownership alone is insufficient"
        );
        let role = "enrollment_role".parse::<RoleId>().unwrap();
        Register::role(Role::new(role.clone(), f.admin.clone()).add_permission(DpnUser))
            .execute(&f.admin, &mut tx)
            .unwrap();
        Grant::account_role(role.clone(), f.registrar.clone())
            .execute(&f.admin, &mut tx)
            .unwrap();
        super::super::Executor::Initial
            .execute_instruction(
                &mut tx,
                &f.registrar,
                Grant::account_role(role, f.customer).into(),
            )
            .expect_err("role grants do not use scoped recipient exception");
    }
    #[test]
    fn dpn_domain_enrollment_revocation_survives_domain_transfer_and_expiry() {
        let mut f = fixture();
        let token: Permission = CanGrantDpnUserForAccountDomain {
            domain: f.domain.clone(),
        }
        .into();
        f.world.domains.insert(
            f.domain.clone(),
            Domain::new(f.domain.clone()).build(&f.customer),
        );
        let selector = crate::sns::selector_for_domain(&f.domain).unwrap();
        let key = crate::sns::record_storage_key(&selector);
        let address = AccountAddress::from_account_id(&f.customer).unwrap();
        let record = NameRecordV1::new(
            selector,
            f.customer.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            100,
            200,
            300,
            Metadata::default(),
        );
        f.world
            .smart_contract_state_mut_for_testing()
            .insert(key, record.encode());
        let state = state_after_genesis(f.world);
        for now in [50, 101] {
            let mut block = state.block(BlockHeader::new(
                nonzero!(2_u64),
                Some(state.view().latest_block_hash().unwrap()),
                None,
                now,
                0,
            ));
            let mut tx = block.transaction();
            assert!(
                initial_permission_revocation_allowed(&tx, &f.admin, &token).unwrap(),
                "direct admin can retire a capability after transfer or lease expiry"
            );
            assert_eq!(
                initial_permission_revocation_allowed(&tx, &f.customer, &token).unwrap(),
                now == 50,
                "new non-admin owner may revoke only while its exact lease is live"
            );
            assert!(!initial_permission_delegation_allowed(&tx, &f.customer, &token).unwrap());
            assert!(!initial_permission_delegation_allowed(&tx, &f.admin, &token).unwrap());
            super::super::Executor::Initial
                .execute_instruction(
                    &mut tx,
                    &f.admin,
                    Revoke::account_permission(token.clone(), f.registrar.clone()).into(),
                )
                .unwrap();
        }
    }
    #[test]
    fn dpn_domain_enrollment_exact_payload_roundtrip_and_rejections() {
        let token: Permission = CanGrantDpnUserForAccountDomain {
            domain: DomainId::try_new("nevo", "dpn").unwrap(),
        }
        .into();
        validate_initial_permission_payload_constraints(&token).unwrap();
        assert_eq!(
            Permission::from(CanGrantDpnUserForAccountDomain::try_from(&token).unwrap()),
            token
        );
        for payload in [
            "null",
            "{}",
            "[]",
            r#"{"domain":"nevo.dpn","extra":true}"#,
            r#"{"domain":"nevo"}"#,
        ] {
            let permission = Permission::new(
                "CanGrantDpnUserForAccountDomain".to_owned(),
                Json::from_raw_json(payload.to_owned()).unwrap(),
            );
            assert!(
                validate_initial_permission_payload_constraints(&permission).is_err(),
                "{payload}"
            );
        }
    }
}
