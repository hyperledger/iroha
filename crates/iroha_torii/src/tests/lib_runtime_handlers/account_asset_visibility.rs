#[cfg(feature = "app_api")]
mod account_asset_visibility {
    //! Exact account reads retain definition grants and authorized balance routes.

    use super::*;
    use iroha_data_model::asset::AssetBalanceScope;
    use iroha_executor_data_model::permission::query::CanReadAccountData;

    struct Fixture {
        app: SharedAppState,
        target: AccountId,
        sibling: AccountId,
        reader: AccountId,
        global: AssetDefinitionId,
        public: AssetDefinitionId,
        private: AssetDefinitionId,
        scoped: AssetDefinitionId,
    }

    impl Fixture {
        fn new() -> Self {
            let target = checked_torii_test_account_id(0xe1, "asset visibility target");
            let reader = checked_torii_test_account_id(0xe2, "asset visibility reader");
            let sibling = checked_torii_test_account_id(0xe3, "asset visibility sibling");
            let public_domain = DomainId::try_new("treasury", "governance").expect("public domain");
            let private_domain = DomainId::try_new("vault", "restricted").expect("private domain");
            let definition = |domain: &DomainId, name: &str| {
                AssetDefinitionId::derive_from_components(domain.clone(), name.parse().unwrap())
            };
            let global = definition(&public_domain, "global_home");
            let public = definition(&public_domain, "public_home");
            let private = definition(&private_domain, "private_home");
            let scoped = definition(&private_domain, "private_buckets");
            let world = World::with_assets(
                [
                    Domain::new(public_domain.clone()).build(&target),
                    Domain::new(private_domain.clone()).build(&target),
                ],
                [
                    Account::new(target.clone()).build(&target),
                    Account::new(sibling.clone()).build(&sibling),
                    Account::new(reader.clone()).build(&reader),
                ],
                [
                    AssetDefinition::numeric(
                        global.clone(),
                        "Global home",
                        AssetBalancePolicy::Global,
                        None,
                    )
                    .build(&target),
                    AssetDefinition::numeric(
                        public.clone(),
                        "Public home",
                        AssetBalancePolicy::Global,
                        Some(public_domain),
                    )
                    .build(&target),
                    AssetDefinition::numeric(
                        private.clone(),
                        "Private home",
                        AssetBalancePolicy::Global,
                        Some(private_domain.clone()),
                    )
                    .build(&target),
                    AssetDefinition::numeric(
                        scoped.clone(),
                        "Private buckets",
                        AssetBalancePolicy::DataspaceRestricted,
                        Some(private_domain),
                    )
                    .build(&target),
                ],
                [
                    Asset::new(
                        AssetId::new(global.clone(), target.clone()),
                        Quantity::from(10_u32),
                    ),
                    Asset::new(
                        AssetId::new(public.clone(), target.clone()),
                        Quantity::from(30_u32),
                    ),
                    Asset::new(
                        AssetId::new(private.clone(), target.clone()),
                        Quantity::from(20_u32),
                    ),
                    Asset::new(
                        AssetId::new(private.clone(), sibling.clone()),
                        Quantity::from(99_u32),
                    ),
                    Asset::new(
                        AssetId::with_scope(
                            scoped.clone(),
                            target.clone(),
                            AssetBalanceScope::Dataspace(DataSpaceId::new(1)),
                        ),
                        Quantity::from(50_u32),
                    ),
                    Asset::new(
                        AssetId::with_scope(
                            scoped.clone(),
                            target.clone(),
                            AssetBalanceScope::Dataspace(DataSpaceId::new(10)),
                        ),
                        Quantity::from(40_u32),
                    ),
                ],
                [],
            );
            let app = mk_app_state_for_tests_with_world_and_nexus(
                world,
                private_ingress_nexus_for_test(),
            );
            Self {
                app,
                target,
                sibling,
                reader,
                global,
                public,
                private,
                scoped,
            }
        }

        fn visibility(
            &self,
            caller: &AccountId,
            route: RoutingDecision,
        ) -> routing::DataspaceReadVisibility {
            torii_account_assets_route_visibility(
                self.app.as_ref(),
                &ToriiFanoutRouteScopeV1::TargetAccount {
                    account_id: self.target.to_string(),
                    caller_account_id: Some(caller.to_string()),
                },
                &self.target.to_string(),
                route,
            )
            .expect("authorized exact-account collection")
        }

        async fn assert_rows(
            &self,
            visibility: &routing::DataspaceReadVisibility,
            private_visible: bool,
        ) {
            // GET and POST/query execute this same collection owner with the
            // freshly reauthorized account visibility from the routed handler.
            let page = routing::collection_sources::execute_collection_local(
                None,
                &self.app.state,
                &routing::collection_sources::CollectionTarget::AccountAssets(
                    self.target.to_string(),
                ),
                iroha_torii_shared::list_query::ListQuery::new(),
                &self.app.telemetry_handle(),
                visibility,
            )
            .await
            .expect("account assets collection");
            let mut expected = BTreeMap::from([
                ((self.global.to_string(), "global".to_owned()), "10"),
                ((self.public.to_string(), "global".to_owned()), "30"),
            ]);
            if private_visible {
                expected.insert((self.private.to_string(), "global".to_owned()), "20");
                expected.insert((self.scoped.to_string(), "dataspace:1".to_owned()), "50");
            }
            assert_eq!(page.items.len(), expected.len());
            for row in page.items {
                assert_eq!(
                    row["account_id"].as_str(),
                    Some(self.target.to_string().as_str())
                );
                let key = (
                    row["asset"].as_str().expect("asset ID").to_owned(),
                    row["scope"].as_str().expect("balance scope").to_owned(),
                );
                assert_eq!(
                    row["quantity"].as_str(),
                    Some(
                        expected
                            .remove(&key)
                            .expect("authorized bucket exactly once")
                    )
                );
            }
            assert!(expected.is_empty());
        }

        fn revoke(&self, permission: &Permission) {
            let height = self
                .app
                .state
                .latest_block_header_fast()
                .map_or(1, |header| header.height().get().saturating_add(1));
            let mut block = self.app.state.block(BlockHeader::new(
                NonZeroU64::new(height).expect("height"),
                None,
                None,
                0,
                0,
            ));
            let mut tx = block.transaction();
            assert!(
                tx.world_mut_for_testing()
                    .remove_account_permission(&self.reader, permission)
            );
            tx.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit read revocation");
        }
    }

    #[tokio::test]
    async fn account_assets_retain_current_definition_grants_without_expanding_balances() {
        let fixture = Fixture::new();
        let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        for caller in [&fixture.target, &fixture.reader] {
            fixture
                .assert_rows(&fixture.visibility(caller, route), false)
                .await;
        }
        grant_account_permission_for_test(
            &fixture.app,
            &fixture.reader,
            CanReadAccountData {
                account: fixture.target.clone(),
            }
            .into(),
        );
        fixture
            .assert_rows(&fixture.visibility(&fixture.reader, route), false)
            .await;

        let global: Permission = CanReadAllLedgerData.into();
        grant_account_permission_for_test(&fixture.app, &fixture.reader, global.clone());
        let visibility = fixture.visibility(&fixture.reader, route);
        assert!(visibility.can_read_all());
        assert_eq!(visibility.exact_account_id(), Some(&fixture.target));
        fixture.assert_rows(&visibility, true).await;
        let world = fixture.app.state.world_view();
        assert!(!visibility.allows_account(&world, &fixture.sibling));
        assert!(!visibility.allows_asset(
            &world,
            &AssetId::new(fixture.private.clone(), fixture.sibling.clone())
        ));
        assert!(!visibility.allows_asset(
            &world,
            &AssetId::with_scope(
                fixture.scoped.clone(),
                fixture.target.clone(),
                AssetBalanceScope::Dataspace(DataSpaceId::new(10)),
            )
        ));
        drop(world);
        fixture.revoke(&global);
        let visibility = fixture.visibility(&fixture.reader, route);
        assert!(!visibility.can_read_all());
        fixture.assert_rows(&visibility, false).await;

        // A separate definition-home grant also opens the definition without
        // adding the unrelated private balance route to the target account.
        let restricted: Permission = CanReadRestrictedDataspace {
            dataspace: DataSpaceId::new(10),
        }
        .into();
        grant_account_permission_for_test(&fixture.app, &fixture.reader, restricted.clone());
        fixture
            .assert_rows(&fixture.visibility(&fixture.reader, route), true)
            .await;
        fixture.revoke(&restricted);
        fixture
            .assert_rows(&fixture.visibility(&fixture.reader, route), false)
            .await;
    }

    #[tokio::test]
    async fn account_assets_execute_complete_authorized_set_on_either_public_route() {
        let fixture = Fixture::new();
        grant_account_permission_for_test(
            &fixture.app,
            &fixture.reader,
            CanReadAllLedgerData.into(),
        );
        let routes = torii_account_assets_read_routes(
            fixture.app.as_ref(),
            &fixture.target,
            Some(&fixture.reader),
        )
        .expect("authorized target routes");
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .all(|route| route.dataspace_id != DataSpaceId::new(10))
        );
        for route in routes {
            fixture
                .assert_rows(&fixture.visibility(&fixture.reader, route), true)
                .await;
        }
    }

    #[test]
    fn exact_account_visibility_keeps_balance_routes_separate_from_definition_grants() {
        let fixture = Fixture::new();
        let world = fixture.app.state.world_view();
        for can_read_all in [false, true] {
            let visibility = routing::DataspaceReadVisibility::new(
                BTreeSet::from([
                    DataSpaceId::UNIVERSAL,
                    DataSpaceId::new(1),
                    DataSpaceId::new(10),
                ]),
                can_read_all,
            )
            .with_exact_account(
                BTreeSet::from([DataSpaceId::new(1), DataSpaceId::new(10)]),
                fixture.target.clone(),
            );
            assert!(visibility.allows_asset_definition(&world, &fixture.private));
            assert!(
                !visibility.allows_asset(
                    &world,
                    &AssetId::new(fixture.private.clone(), fixture.target.clone())
                ),
                "a visible global definition does not authorize its universal balance bucket"
            );
            for dataspace in [DataSpaceId::new(1), DataSpaceId::new(10)] {
                assert!(visibility.allows_asset(
                    &world,
                    &AssetId::with_scope(
                        fixture.scoped.clone(),
                        fixture.target.clone(),
                        AssetBalanceScope::Dataspace(dataspace),
                    )
                ));
            }
            assert!(!visibility.allows_account(&world, &fixture.sibling));
        }
    }

    #[test]
    fn exact_account_visibility_digest_binds_account_and_balance_authority() {
        let fixture = Fixture::new();
        let visibility = || {
            routing::DataspaceReadVisibility::new(
                BTreeSet::from([
                    DataSpaceId::UNIVERSAL,
                    DataSpaceId::new(1),
                    DataSpaceId::new(10),
                ]),
                true,
            )
        };
        let exact = |account, routes| {
            visibility()
                .with_exact_account(routes, account)
                .visible_route_set_digest()
        };
        let baseline = exact(
            fixture.target.clone(),
            BTreeSet::from([DataSpaceId::UNIVERSAL]),
        );
        assert_ne!(baseline, visibility().visible_route_set_digest());
        assert_ne!(
            baseline,
            exact(
                fixture.sibling.clone(),
                BTreeSet::from([DataSpaceId::UNIVERSAL])
            )
        );
        assert_ne!(
            baseline,
            exact(
                fixture.target,
                BTreeSet::from([DataSpaceId::UNIVERSAL, DataSpaceId::new(1)])
            )
        );
    }
}
