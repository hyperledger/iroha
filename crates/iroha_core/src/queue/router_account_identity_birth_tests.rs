fn account_identity_birth_fixture(
    private_root: bool,
    multiscope_registrar: bool,
    typed_rule: bool,
) -> (
    crate::state::State,
    ConfigLaneRouter,
    AccountId,
    iroha_crypto::KeyPair,
    AccountId,
) {
    let (authority, signer) = gen_account_in("identity-registrar");
    let (target, _) = gen_account_in("new-universal-identity");
    let home = DataSpaceId::new(10);
    let catalog = if private_root {
        DataSpaceCatalog::new(vec![iroha_data_model::nexus::DataSpaceMetadata {
            id: home,
            alias: "paynet".into(),
            description: None,
            fault_tolerance: 1,
        }])
        .unwrap()
    } else {
        dataspace_catalog(&[(home, "paynet"), (DataSpaceId::new(11), "other")])
    };
    let application_lane = if private_root {
        LaneId::SINGLE
    } else {
        LaneId::new(3)
    };
    let lane_catalog = if private_root {
        catalog_with_lane_dataspaces(&[(LaneId::SINGLE, home)])
    } else {
        catalog_with_lane_dataspaces(&[
            (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            (application_lane, home),
            (LaneId::new(4), DataSpaceId::new(11)),
        ])
    };
    let mut rules = Vec::new();
    if typed_rule {
        rules.push(LaneRoutingRule {
            lane: application_lane,
            dataspace: Some(home),
            matcher: LaneRoutingMatcher {
                account: Some("*@paynet".into()),
                instruction: Some("register::account".into()),
                description: None,
            },
        });
    }
    rules.push(LaneRoutingRule {
        lane: application_lane,
        dataspace: Some(home),
        matcher: LaneRoutingMatcher {
            account: Some("*@paynet".into()),
            ..Default::default()
        },
    });
    let router = ConfigLaneRouter::new(
        LaneRoutingPolicy {
            default_lane: LaneId::SINGLE,
            default_dataspace: if private_root {
                home
            } else {
                DataSpaceId::UNIVERSAL
            },
            rules,
        },
        catalog.clone(),
        lane_catalog,
    );
    let mut scope = account_scope_entry(home);
    if multiscope_registrar {
        scope.ensure_dataspace(DataSpaceId::UNIVERSAL);
    }
    let mut state = if private_root {
        // Install the authenticated private-root metadata before validating its
        // H0 geometry; a Global fixture cannot drop dataspace zero in place.
        let mut world = crate::state::World::new();
        let alias = AccountAlias::new("scope_0".parse().unwrap(), None, home);
        let (id, account) = Account::new(authority.clone())
            .with_label(Some(alias.clone()))
            .build(&authority)
            .into_key_value();
        world.accounts.insert(id, account);
        world
            .account_aliases
            .insert(alias.clone(), authority.clone());
        world
            .account_aliases_by_account
            .insert(authority.clone(), BTreeSet::from([alias.clone()]));
        world.replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(
                alias.clone(),
                authority.clone(),
            ),
        );
        let selector = crate::sns::selector_for_account_alias(&alias, &catalog).unwrap();
        let address = AccountAddress::from_account_id(&authority).unwrap();
        let record = NameRecordV1::new(
            selector.clone(),
            authority.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        world
            .smart_contract_state_mut_for_testing()
            .insert(crate::sns::record_storage_key(&selector), record.encode());
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                    parent_network_id: super::super::queue_test_network_id(),
                    dataspace_id: home,
                },
            ))
            .unwrap();
        parameters.commit();
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.routing_policy = router.policy.as_ref().clone();
        nexus.dataspace_catalog = catalog.clone();
        nexus.configured_dataspace_catalog = catalog;
        nexus.lane_catalog = router.lane_catalog.as_ref().clone();
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        crate::state::State::new_with_nexus_for_testing(
            world,
            nexus,
            crate::query::store::LiveQueryStore::start_test(),
        )
    } else {
        state_with_account_scope_entries(&[(authority.clone(), scope)], catalog)
    };
    install_router_nexus(&mut state, &router);
    (state, router, authority, signer, target)
}

fn account_identity_birth_native_route(
    view: &StateView<'_>,
    tx: &AcceptedTransaction<'_>,
    private_root: bool,
    typed_rule: bool,
) -> RoutingDecision {
    account_identity_birth_native_route_with_selector(
        view,
        tx,
        private_root,
        typed_rule.then_some("register::account"),
    )
}

fn account_identity_birth_native_route_with_selector(
    view: &StateView<'_>,
    tx: &AcceptedTransaction<'_>,
    private_root: bool,
    typed_selector: Option<&str>,
) -> RoutingDecision {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        parameter::system::SumeragiParameters,
        sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneFrontier, SumeragiLanePolicy, SumeragiLaneRecord,
            SumeragiLaneRoute, SumeragiLaneState,
        },
    };
    let mut lanes = SumeragiLaneState::default();
    let mut fixed = Vec::new();
    for lane in view
        .nexus()
        .lane_catalog
        .lanes()
        .iter()
        .filter(|lane| lane.id != LaneId::SINGLE)
    {
        fixed.push(SumeragiFixedLane {
            lane: lane.id,
            dataspace: lane.dataspace_id,
            committee: Vec::new(),
        });
        lanes.upsert(SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: lane.id,
            dataspace: lane.dataspace_id,
            incarnation: [1; 32],
            params: SumeragiParameters::default(),
            committee: Vec::new(),
            created_at: 0,
            active_from: 2,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 2,
            rescued: 0,
        });
    }
    let lane = if private_root {
        LaneId::SINGLE
    } else {
        LaneId::new(3)
    };
    let mut routes = Vec::new();
    if let Some(selector) = typed_selector {
        routes.push(SumeragiLaneRoute {
            lane,
            account: Some("*@paynet".into()),
            instruction: Some(selector.into()),
        });
    }
    routes.push(SumeragiLaneRoute {
        lane,
        account: Some("*@paynet".into()),
        instruction: None,
    });
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 16,
        max_merge_blocks: 32,
        stall_window: 256,
        lane_params: SumeragiParameters::default(),
        fixed,
        routes,
        autoscale: None,
    };
    let root_scope = if private_root {
        SumeragiRootScope::Dataspace {
            parent_network_id: super::super::queue_test_network_id(),
            dataspace_id: DataSpaceId::new(10),
        }
    } else {
        SumeragiRootScope::Global
    };
    crate::sumeragi::lanes::routing::RoutingInputs {
        root_scope: Some(root_scope),
        policy: Some(&policy),
        lanes: &lanes,
        dataspaces: &view.nexus().dataspace_catalog,
        world: view.world(),
        ledger_time_ms: 0,
    }
    .execution_route(tx, 3)
    .expect("original native routing read")
    .expect("admitted native route")
}

fn account_identity_birth_instruction(target: AccountId) -> InstructionBox {
    Register::account(
        Account::new(target).with_uaid(Some(UniversalAccountId::from_hash(Hash::new(
            b"uaid-only-account-identity-birth",
        )))),
    )
    .into()
}

#[test]
fn account_identity_birth_scoped_registrar_keeps_native_and_physical_root_agreement() {
    for multiscope in [false, true] {
        let (state, router, authority, signer, target) =
            account_identity_birth_fixture(false, multiscope, false);
        for batch in [false, true] {
            let body = vec![account_identity_birth_instruction(target.clone())];
            let tx = if batch {
                sample_executable_transaction(
                    &authority,
                    signer.private_key(),
                    Executable::Batch(
                        body.into_iter()
                            .map(ExecutableBatchItem::Instruction)
                            .collect(),
                    ),
                )
            } else {
                sample_transaction(&authority, signer.private_key(), body)
            };
            let view = state.view();
            let native = account_identity_birth_native_route(&view, &tx, false, false);
            assert_eq!(native.dataspace_id, DataSpaceId::UNIVERSAL);
            let physical = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
                view.nexus(),
                view.world(),
                &tx,
                2,
                0,
            )
            .unwrap();
            assert_eq!(
                physical
                    .require_dataspace(native)
                    .unwrap()
                    .decision()
                    .dataspace_id,
                DataSpaceId::UNIVERSAL
            );
            assert_eq!(
                router.try_route_with_view(&tx, &view).unwrap().dataspace_id,
                DataSpaceId::UNIVERSAL
            );
            assert!(!rule_matches(&router.policy.rules[0], &tx, Some(&view)).unwrap());
        }
    }
}

#[test]
fn account_identity_birth_private_root_keeps_its_configured_profile() {
    let (state, router, authority, signer, target) =
        account_identity_birth_fixture(true, false, false);
    let tx = sample_transaction(
        &authority,
        signer.private_key(),
        vec![account_identity_birth_instruction(target)],
    );
    let view = state.view();
    let scope = view.world().account_scope_hierarchy(&authority).unwrap();
    assert_eq!(
        scope.keys().copied().collect::<Vec<_>>(),
        vec![DataSpaceId::new(10)]
    );
    assert!(account_matches_alias_scope("paynet", &authority, &view).unwrap());
    assert!(
        view.nexus()
            .dataspace_catalog
            .by_id(DataSpaceId::UNIVERSAL)
            .is_none()
    );
    let native = account_identity_birth_native_route(&view, &tx, true, false);
    let physical = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
        view.nexus(),
        view.world(),
        &tx,
        2,
        0,
    )
    .unwrap();
    assert_eq!(native.dataspace_id, DataSpaceId::new(10));
    assert_eq!(
        physical.require_dataspace(native).unwrap().decision(),
        router.try_route_with_view(&tx, &view).unwrap()
    );
}

#[test]
fn account_identity_birth_explicit_typed_policy_is_honored_and_conflicts_still_refuse() {
    let (state, router, authority, signer, target) =
        account_identity_birth_fixture(false, true, true);
    let tx = sample_transaction(
        &authority,
        signer.private_key(),
        vec![account_identity_birth_instruction(target)],
    );
    let view = state.view();
    let physical = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
        view.nexus(),
        view.world(),
        &tx,
        2,
        0,
    )
    .unwrap();
    let explicit_native = account_identity_birth_native_route(&view, &tx, false, true);
    assert_eq!(explicit_native.dataspace_id, DataSpaceId::new(10));
    assert_eq!(
        physical
            .require_dataspace(explicit_native)
            .unwrap()
            .decision(),
        router.try_route_with_view(&tx, &view).unwrap()
    );
    assert!(rule_matches(&router.policy.rules[0], &tx, Some(&view)).unwrap());
    let root_native = account_identity_birth_native_route(&view, &tx, false, false);
    assert_eq!(root_native.dataspace_id, DataSpaceId::UNIVERSAL);
    assert!(matches!(
        physical.require_dataspace(root_native),
        Err(crate::queue::policy_route::PhysicalPolicyRouteRejection::DataspaceMismatch)
    ));
}

#[test]
fn account_identity_birth_labeled_and_mixed_business_bodies_keep_application_placement() {
    let (state, router, authority, signer, target) =
        account_identity_birth_fixture(false, true, false);
    let view = state.view();
    let labeled = Register::account(Account::new(target.clone()).with_label(Some(account_alias(
        "merchant@paynet",
        &view.nexus().dataspace_catalog,
    ))))
    .into();
    let bodies = [
        vec![labeled],
        vec![
            account_identity_birth_instruction(target),
            Register::domain(Domain::new(
                DomainId::try_new("merchant", "paynet").unwrap(),
            ))
            .into(),
        ],
    ];
    for body in bodies {
        for batch in [false, true] {
            let tx = if batch {
                sample_executable_transaction(
                    &authority,
                    signer.private_key(),
                    Executable::Batch(
                        body.clone()
                            .into_iter()
                            .map(ExecutableBatchItem::Instruction)
                            .collect(),
                    ),
                )
            } else {
                sample_transaction(&authority, signer.private_key(), body.clone())
            };
            let native = account_identity_birth_native_route(&view, &tx, false, false);
            let physical = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
                view.nexus(),
                view.world(),
                &tx,
                2,
                0,
            )
            .unwrap();
            assert_eq!(native.dataspace_id, DataSpaceId::new(10));
            assert_eq!(
                physical.require_dataspace(native).unwrap().decision(),
                router.try_route_with_view(&tx, &view).unwrap()
            );
            assert!(rule_matches(&router.policy.rules[0], &tx, Some(&view)).unwrap());
        }
    }
}

#[test]
fn account_identity_birth_mixed_cross_dataspace_body_keeps_explicit_refusal() {
    let (state, router, authority, signer, target) =
        account_identity_birth_fixture(false, true, false);
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().unwrap(),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let tx = sample_transaction_with_metadata(
        &authority,
        signer.private_key(),
        vec![
            account_identity_birth_instruction(target),
            Register::domain(Domain::new(
                DomainId::try_new("merchant", "paynet").unwrap(),
            ))
            .into(),
            Register::domain(Domain::new(DomainId::try_new("merchant", "other").unwrap())).into(),
        ],
        metadata,
    );
    let view = state.view();
    assert!(matches!(
        router.try_route_with_view(&tx, &view),
        Err(RoutingResolveError::ConflictingTransactionDataspaceTargets { .. })
    ));
    assert!(matches!(
        native_execution_target(&tx, &view.nexus().dataspace_catalog, view.world(), 0),
        Err(RoutingResolveError::ConflictingTransactionDataspaceTargets { .. })
    ));
    assert!(
        crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
            view.nexus(),
            view.world(),
            &tx,
            2,
            0
        )
        .is_err()
    );
    assert!(rule_matches(&router.policy.rules[0], &tx, Some(&view)).unwrap());
}

fn account_identity_birth_multisig_instruction(
    member: &AccountId,
    home_domain: Option<DomainId>,
) -> InstructionBox {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    use iroha_executor_data_model::isi::multisig::{MultisigRegister, MultisigSpec};

    let policy = MultisigPolicy::new(
        1,
        vec![MultisigMember::new(member.try_signatory().unwrap().clone(), 1).unwrap()],
    )
    .unwrap();
    let account = AccountId::new_multisig(policy);
    let spec = MultisigSpec {
        signatories: BTreeMap::from([(member.clone(), 1)]),
        quorum: std::num::NonZeroU16::new(1).unwrap(),
        transaction_ttl_ms: std::num::NonZeroU64::new(3_600_000).unwrap(),
    };
    // This conversion is the API's actual signed CustomInstruction wrapper.
    MultisigRegister::with_account(account, home_domain, spec)
        .with_uaid(Some(UniversalAccountId::from_hash(Hash::new(
            b"company-account-identity-birth",
        ))))
        .into()
}

#[test]
fn account_identity_birth_multisig_custom_wrapper_keeps_root_agreement() {
    for private_root in [false, true] {
        for multiscope in [false, true] {
            if private_root && multiscope {
                continue;
            }
            let (state, router, authority, signer, target) =
                account_identity_birth_fixture(private_root, multiscope, false);
            let registration = account_identity_birth_multisig_instruction(&authority, None);
            assert!(registration.as_any().is::<CustomInstruction>());
            for body in [
                vec![registration.clone()],
                vec![
                    account_identity_birth_instruction(target.clone()),
                    registration.clone(),
                ],
            ] {
                for batch in [false, true] {
                    let executable = if batch {
                        Executable::Batch(
                            body.clone()
                                .into_iter()
                                .map(ExecutableBatchItem::Instruction)
                                .collect(),
                        )
                    } else {
                        Executable::Instructions(body.clone().into())
                    };
                    let tx =
                        sample_executable_transaction(&authority, signer.private_key(), executable);
                    assert!(transaction_registers_only_unlabeled_accounts(&tx).unwrap());
                    let view = state.view();
                    let native =
                        account_identity_birth_native_route(&view, &tx, private_root, false);
                    let expected = if private_root {
                        DataSpaceId::new(10)
                    } else {
                        DataSpaceId::UNIVERSAL
                    };
                    assert_eq!(native.dataspace_id, expected);
                    let physical =
                        crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
                            view.nexus(),
                            view.world(),
                            &tx,
                            2,
                            0,
                        )
                        .unwrap();
                    assert_eq!(
                        physical.require_dataspace(native).unwrap().decision(),
                        router.try_route_with_view(&tx, &view).unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn account_identity_birth_multisig_excludes_home_domain_and_nonbirth_bodies() {
    use iroha_executor_data_model::isi::multisig::{MultisigCancel, MultisigInvalidateOutstanding};

    let (state, router, authority, signer, _) = account_identity_birth_fixture(false, true, false);
    let registration = account_identity_birth_multisig_instruction(&authority, None);
    let proposal_instructions: Vec<InstructionBox> = vec![
        Register::domain(Domain::new(
            DomainId::try_new("merchant", "paynet").unwrap(),
        ))
        .into(),
    ];
    let hash = HashOf::new(&proposal_instructions);
    let bodies = [
        vec![account_identity_birth_multisig_instruction(
            &authority,
            Some(DomainId::try_new("merchant", "paynet").unwrap()),
        )],
        vec![registration.clone(), proposal_instructions[0].clone()],
        vec![
            MultisigPropose::new(
                authority.clone(),
                test_nonce(&hash),
                proposal_instructions,
                None,
            )
            .into(),
        ],
        vec![
            MultisigCancel {
                account: authority.clone(),
                proposal_id: test_id(&authority, &hash),
                instructions_hash: hash,
            }
            .into(),
        ],
        vec![
            MultisigInvalidateOutstanding {
                account: authority.clone(),
            }
            .into(),
        ],
    ];
    for body in bodies {
        for batch in [false, true] {
            let executable = if batch {
                Executable::Batch(
                    body.clone()
                        .into_iter()
                        .map(ExecutableBatchItem::Instruction)
                        .collect(),
                )
            } else {
                Executable::Instructions(body.clone().into())
            };
            let tx = sample_executable_transaction(&authority, signer.private_key(), executable);
            assert!(!transaction_registers_only_unlabeled_accounts(&tx).unwrap());
            assert!(rule_matches(&router.policy.rules[0], &tx, Some(&state.view())).unwrap());
        }
    }
    let tx = sample_executable_transaction(
        &authority,
        signer.private_key(),
        Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(registration),
                ExecutableBatchItem::ContractCall(sample_contract_invocation(
                    &authority,
                    DataSpaceId::new(10),
                    1,
                )),
            ]
            .into(),
        ),
    );
    assert!(!transaction_registers_only_unlabeled_accounts(&tx).unwrap());
}

#[test]
fn account_identity_birth_multisig_typed_policy_and_original_decode_refusal_survive() {
    let (mut state, router, authority, signer, _) =
        account_identity_birth_fixture(false, true, false);
    let instruction = account_identity_birth_multisig_instruction(&authority, None);
    let selector = Instruction::id(&*instruction).to_owned();
    let mut policy = router.policy.as_ref().clone();
    policy.rules.insert(
        0,
        LaneRoutingRule {
            lane: LaneId::new(3),
            dataspace: Some(DataSpaceId::new(10)),
            matcher: LaneRoutingMatcher {
                account: Some("*@paynet".into()),
                instruction: Some(selector.clone()),
                description: None,
            },
        },
    );
    let router = ConfigLaneRouter::new(
        policy,
        router.dataspace_catalog.as_ref().clone(),
        router.lane_catalog.as_ref().clone(),
    );
    install_router_nexus(&mut state, &router);
    let tx = sample_transaction(&authority, signer.private_key(), vec![instruction.clone()]);
    let view = state.view();
    let native =
        account_identity_birth_native_route_with_selector(&view, &tx, false, Some(&selector));
    assert_eq!(native.dataspace_id, DataSpaceId::new(10));
    let physical = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
        view.nexus(),
        view.world(),
        &tx,
        2,
        0,
    )
    .unwrap();
    assert!(physical.require_dataspace(native).is_ok());
    assert!(matches!(
        physical.require_dataspace(account_identity_birth_native_route(
            &view, &tx, false, false
        )),
        Err(crate::queue::policy_route::PhysicalPolicyRouteRejection::DataspaceMismatch)
    ));
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            let direct = multisig_instruction_with_original_decode(&*instruction).unwrap_err();
            let classified = transaction_registers_only_unlabeled_accounts(&tx).unwrap_err();
            let fallback = authority_dataspace_target_with_world(Some(view.world()), &tx, Some(0))
                .unwrap_err();
            for actual in [&classified, &fallback] {
                assert_eq!(actual.reason(), direct.reason());
                let observed = actual.decode_refusal().unwrap();
                let original = direct.decode_refusal().unwrap();
                assert_eq!(observed.kind(), original.kind());
                assert_eq!(observed.resource_error(), original.resource_error());
            }
            assert!(account_placement_applies_to_body(Some("*@paynet"), None, &tx).is_err());
            assert!(rule_matches(&router.policy.rules[1], &tx, Some(&view)).is_err());
            assert!(
                matchers_match_with_world(
                    Some("*@paynet"),
                    None,
                    &tx,
                    &view.nexus().dataspace_catalog,
                    view.world(),
                    Some(0),
                )
                .is_err()
            );
        },
    );
    assert!(transaction_registers_only_unlabeled_accounts(&tx).unwrap());
}

#[test]
fn account_identity_birth_fee_enrollment_routes_by_program_owner() {
    use iroha_data_model::{
        isi::nexus::{EnrollFeeSponsorBeneficiary, UnenrollFeeSponsorBeneficiary},
        nexus::FeeSponsorProgramId,
    };

    for private_root in [false, true] {
        for scopes in [
            vec![DataSpaceId::UNIVERSAL],
            vec![DataSpaceId::UNIVERSAL, DataSpaceId::new(10)],
            vec![DataSpaceId::new(10)],
        ] {
            if private_root && scopes != vec![DataSpaceId::new(10)] {
                continue;
            }
            let (mut state, router, authority, signer, beneficiary) =
                account_identity_birth_fixture(private_root, !private_root, false);
            let sponsor = if private_root {
                authority.clone()
            } else {
                let (sponsor, _) = gen_account_in("fee-program-owner");
                let mut registrar_scope = account_scope_entry(DataSpaceId::new(10));
                registrar_scope.ensure_dataspace(DataSpaceId::UNIVERSAL);
                let mut sponsor_scope = account_scope_entry(scopes[0]);
                for scope in scopes.iter().skip(1) {
                    sponsor_scope.ensure_dataspace(*scope);
                }
                state = state_with_account_scope_entries(
                    &[
                        (authority.clone(), registrar_scope),
                        (sponsor.clone(), sponsor_scope),
                    ],
                    router.dataspace_catalog.as_ref().clone(),
                );
                install_router_nexus(&mut state, &router);
                sponsor
            };
            let program = FeeSponsorProgramId::new(sponsor, "onboarding".parse().unwrap());
            let instructions: [InstructionBox; 2] = [
                EnrollFeeSponsorBeneficiary {
                    program_id: program.clone(),
                    beneficiary: beneficiary.clone(),
                }
                .into(),
                UnenrollFeeSponsorBeneficiary {
                    program_id: program,
                    beneficiary: beneficiary.clone(),
                }
                .into(),
            ];
            let expected = if scopes == vec![DataSpaceId::new(10)] {
                DataSpaceId::new(10)
            } else {
                DataSpaceId::UNIVERSAL
            };
            for instruction in instructions {
                assert!(instruction_transaction_dataspace_target_needs_state(
                    &*instruction
                ));
                for batch in [false, true] {
                    let executable = if batch {
                        Executable::Batch(
                            vec![ExecutableBatchItem::Instruction(instruction.clone())].into(),
                        )
                    } else {
                        Executable::Instructions(vec![instruction.clone()].into())
                    };
                    let tx =
                        sample_executable_transaction(&authority, signer.private_key(), executable);
                    let view = state.view();
                    assert!(view.world().accounts().get(&beneficiary).is_none());
                    let native =
                        account_identity_birth_native_route(&view, &tx, private_root, false);
                    assert_eq!(native.dataspace_id, expected);
                    let physical =
                        crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
                            view.nexus(),
                            view.world(),
                            &tx,
                            2,
                            0,
                        )
                        .unwrap();
                    assert_eq!(
                        physical.require_dataspace(native).unwrap().decision(),
                        router.try_route_with_view(&tx, &view).unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn account_identity_birth_fee_enrollment_refuses_missing_invalid_owner_and_cross_scope() {
    use iroha_data_model::{isi::nexus::EnrollFeeSponsorBeneficiary, nexus::FeeSponsorProgramId};

    let (mut state, router, authority, signer, beneficiary) =
        account_identity_birth_fixture(false, true, false);
    let (missing, _) = gen_account_in("missing-owner");
    let enrollment = |sponsor| -> InstructionBox {
        EnrollFeeSponsorBeneficiary {
            program_id: FeeSponsorProgramId::new(sponsor, "onboarding".parse().unwrap()),
            beneficiary: beneficiary.clone(),
        }
        .into()
    };
    for sponsor in [missing, authority.clone()] {
        if sponsor == authority {
            state.world.account_scope_directory.insert(
                authority.clone(),
                crate::nexus::space_directory::AccountScopeDirectoryEntry::default(),
            );
        }
        let tx = sample_transaction(&authority, signer.private_key(), vec![enrollment(sponsor)]);
        let view = state.view();
        assert!(matches!(
            native_execution_target(&tx, &view.nexus().dataspace_catalog, view.world(), 0),
            Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
        ));
        assert!(
            crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
                view.nexus(),
                view.world(),
                &tx,
                2,
                0
            )
            .is_err()
        );
    }
    let mut invalid = account_scope_entry(DataSpaceId::new(999));
    invalid.bind_domain(DataSpaceId::new(999), "invalid".parse().unwrap());
    state
        .world
        .account_scope_directory
        .insert(authority.clone(), invalid);
    let tx = sample_transaction(
        &authority,
        signer.private_key(),
        vec![enrollment(authority.clone())],
    );
    assert!(matches!(
        fee_sponsor_enrollment_dataspace_target(
            &*enrollment(authority.clone()),
            Some(state.view().world()),
            Some(0)
        ),
        Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
    ));
    assert!(router.try_route_with_view(&tx, &state.view()).is_err());

    // Exercise the original SNS reader used when no derived directory row is
    // present. Its resource refusal must not become Universal placement.
    let mut directory = state.world.account_scope_directory.block();
    directory.remove(authority.clone());
    directory.commit();
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            assert!(matches!(
                fee_sponsor_enrollment_dataspace_target(
                    &*enrollment(authority.clone()),
                    Some(state.view().world()),
                    Some(0),
                ),
                Err(RoutingResolveError::Deferred(_))
            ));
        },
    );

    let (state, _, authority, signer, beneficiary) =
        account_identity_birth_fixture(false, true, false);
    let mut metadata = Metadata::default();
    metadata.insert(
        AMX_POLICY_METADATA_KEY.parse().unwrap(),
        iroha_primitives::json::Json::new(AMX_POLICY_REJECT_CROSS_DATASPACE),
    );
    let tx = sample_transaction_with_metadata(
        &authority,
        signer.private_key(),
        vec![
            EnrollFeeSponsorBeneficiary {
                program_id: FeeSponsorProgramId::new(authority.clone(), "mixed".parse().unwrap()),
                beneficiary,
            }
            .into(),
            Register::domain(Domain::new(
                DomainId::try_new("merchant", "paynet").unwrap(),
            ))
            .into(),
        ],
        metadata,
    );
    let view = state.view();
    assert!(matches!(
        native_execution_target(&tx, &view.nexus().dataspace_catalog, view.world(), 0),
        Err(RoutingResolveError::ConflictingTransactionDataspaceTargets { .. })
    ));
    assert!(
        crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
            view.nexus(),
            view.world(),
            &tx,
            2,
            0
        )
        .is_err()
    );
}
