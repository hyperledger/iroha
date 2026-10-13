// Canonical retail physical routing; source authority and issuer verification remain native.
use super::*;
use crate::state::{State, World};
use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::{
        RetailDailyLimitPolicyV1, RetailIdentityAttestationBodyV1, RetailIdentityAttestationV1,
        RetailIdentityCommitmentV1, RetailMonetaryPurposeV1,
        retail_daily_limit::RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1,
    },
    domain::Domain,
    isi::retail_daily_limit::{
        ActivateRetailDailyLimitV1, BindRetailIdentityV1, RetailMonetaryMovementV1,
    },
    nexus::{DataSpaceMetadata, LaneConfig},
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::{NumericSpec, Quantity};
use std::{collections::BTreeSet, num::NonZeroU32};

fn fixture() -> (State, Nexus, KeyPair, RetailDailyLimitPolicyV1) {
    let key = KeyPair::from_seed(vec![0x71; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let reserve = AccountId::new(
        KeyPair::from_seed(vec![0x72; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let domain = DomainId::try_new("retail", "bpng").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "kina".parse().unwrap());
    let policy = RetailDailyLimitPolicyV1 {
        asset_definition_id: definition.clone(),
        physical_dataspace: DataSpaceId::new(7),
        revision: 1,
        daily_cap: Quantity::from(5_u32),
        identity_issuer: owner.clone(),
        identity_issuer_public_key: key.public_key().clone(),
        monetary_issuer_account: owner.clone(),
        reserve_account: reserve.clone(),
        institutional_exceptions: BTreeSet::new(),
    };
    policy.validate_shape().unwrap();
    let mut world = World::with(
        [Domain::new(domain.clone()).build(&owner)],
        [
            Account::new(owner.clone()).build(&owner),
            Account::new(reserve).build(&owner),
        ],
        [AssetDefinition::new(
            definition,
            "Kina",
            NumericSpec::fractional(2),
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        )
        .build(&owner)],
    );
    let native = world.smart_contract_state_mut_for_testing();
    native.insert(
        crate::state::retail_daily_limit_state::policy_key(
            &policy.asset_definition_id,
            policy.physical_dataspace,
        ),
        norito::encode_canonical(&policy).unwrap(),
    );
    native.insert(
        crate::state::retail_daily_limit_state::activation_key(&policy.asset_definition_id),
        norito::encode_canonical(
            &crate::state::retail_daily_limit_state::activation_for_policy(&policy, 0).unwrap(),
        )
        .unwrap(),
    );
    let mut nexus = Nexus::default();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: policy.physical_dataspace,
            alias: "bpng".into(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .unwrap();
    nexus.lane_catalog = LaneCatalog::new(
        NonZeroU32::new(3).unwrap(),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(2),
                alias: "bpng".into(),
                dataspace_id: policy.physical_dataspace,
                ..LaneConfig::default()
            },
        ],
    )
    .unwrap();
    // Keep the routing catalog, its derived geometry and this component State
    // aligned. This fixture does not authenticate a native genesis or history.
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    let state = State::new_with_nexus_for_testing(
        world,
        nexus.clone(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    (state, nexus, key, policy)
}

fn instructions(key: &KeyPair, policy: &RetailDailyLimitPolicyV1) -> [InstructionBox; 3] {
    let body = RetailIdentityAttestationBodyV1 {
        domain: RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1.to_owned(),
        asset_definition_id: policy.asset_definition_id.clone(),
        physical_dataspace: policy.physical_dataspace,
        policy_revision: policy.revision,
        account_id: policy.identity_issuer.clone(),
        identity: RetailIdentityCommitmentV1 { digest: [0xA5; 32] },
        uniqueness_evidence_digest: [0xB5; 32],
    };
    [
        ActivateRetailDailyLimitV1 {
            definition: AssetDefinition::new(
                policy.asset_definition_id.clone(),
                "Kina",
                NumericSpec::fractional(2),
                AssetBalancePolicy::DataspaceRestricted,
                Some(DomainId::try_new("retail", "bpng").unwrap()),
            ),
            policy: policy.clone(),
        }
        .into(),
        BindRetailIdentityV1 {
            attestation: RetailIdentityAttestationV1 {
                signature: SignatureOf::try_new(key.private_key(), &body).unwrap(),
                body,
            },
        }
        .into(),
        RetailMonetaryMovementV1 {
            asset_definition_id: policy.asset_definition_id.clone(),
            purpose: RetailMonetaryPurposeV1::MintToReserve,
            retail_account: None,
            amount: Quantity::one(),
            operation_digest: [1; 32],
        }
        .into(),
    ]
}

fn accepted(key: &KeyPair, instruction: InstructionBox) -> AcceptedTransaction<'static> {
    let mut metadata = Metadata::default();
    // These caller fields cannot replace the typed scope or the native policy.
    metadata.insert(
        "dataspace".parse().unwrap(),
        iroha_primitives::json::Json::new(0_u64),
    );
    metadata.insert(
        "lane".parse().unwrap(),
        iroha_primitives::json::Json::new(0_u64),
    );
    sample_transaction_with_metadata(
        &AccountId::new(key.public_key().clone()),
        key.private_key(),
        vec![instruction],
        metadata,
    )
}

#[test]
fn all_retail_instructions_route_from_typed_native_scope_in_both_paths() {
    let (state, nexus, key, policy) = fixture();
    let view = state.view();
    for instruction in instructions(&key, &policy) {
        assert_eq!(
            instruction_transaction_dataspace_target(
                &*instruction,
                Some(&nexus.dataspace_catalog),
                Some(&view)
            )
            .unwrap(),
            Some(policy.physical_dataspace)
        );
        assert_eq!(
            instruction_transaction_dataspace_target_with_world_and_fx_overlay(
                &*instruction,
                Some(&nexus.dataspace_catalog),
                view.world(),
                Some(0),
                &FxCorridorRoutingOverlay::default()
            )
            .unwrap(),
            Some(policy.physical_dataspace)
        );
        let transaction = accepted(&key, instruction);
        let expected = RoutingDecision::new(LaneId::new(2), policy.physical_dataspace);
        assert_eq!(
            evaluate_policy_with_catalog_and_world_at(
                &nexus.routing_policy,
                &nexus.lane_catalog,
                &nexus.dataspace_catalog,
                &transaction,
                view.world(),
                0
            )
            .unwrap(),
            expected
        );
        let route = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
            &nexus,
            view.world(),
            &transaction,
            1,
            0,
        )
        .unwrap();
        assert_eq!(
            route.require_dataspace(expected).unwrap().decision(),
            expected
        );
        assert_eq!(
            route.require_dataspace(RoutingDecision::default()),
            Err(crate::queue::policy_route::PhysicalPolicyRouteRejection::DataspaceMismatch)
        );
    }
}

#[test]
fn retail_declared_scope_substitution_cannot_escape_catalog_or_native_source() {
    let (state, nexus, key, policy) = fixture();
    let view = state.view();
    let mut activation = instructions(&key, &policy)[0]
        .as_any()
        .downcast_ref::<ActivateRetailDailyLimitV1>()
        .unwrap()
        .clone();
    activation.policy.physical_dataspace = DataSpaceId::new(8);
    let mut identity = instructions(&key, &policy)[1]
        .as_any()
        .downcast_ref::<BindRetailIdentityV1>()
        .unwrap()
        .clone();
    identity.attestation.body.physical_dataspace = DataSpaceId::new(8);
    assert!(
        identity
            .attestation
            .verify_for(&policy, &policy.identity_issuer)
            .is_err()
    );
    let substitutions = [
        InstructionBox::from(activation),
        InstructionBox::from(identity),
    ];
    for instruction in substitutions.clone() {
        let transaction = accepted(&key, instruction);
        assert_eq!(
            evaluate_policy_with_catalog_and_world_at(
                &nexus.routing_policy,
                &nexus.lane_catalog,
                &nexus.dataspace_catalog,
                &transaction,
                view.world(),
                0
            ),
            Err(RoutingResolveError::UnknownDataspace {
                dataspace_id: DataSpaceId::new(8)
            })
        );
    }
    // A configured alternate scope is still not the original certified native source.
    let mut expanded = nexus.clone();
    expanded.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: policy.physical_dataspace,
            alias: "bpng".into(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DataSpaceId::new(8),
            alias: "foreign".into(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .unwrap();
    expanded.lane_catalog = LaneCatalog::new(
        NonZeroU32::new(4).unwrap(),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(2),
                alias: "bpng".into(),
                dataspace_id: policy.physical_dataspace,
                ..LaneConfig::default()
            },
            LaneConfig {
                id: LaneId::new(3),
                alias: "foreign".into(),
                dataspace_id: DataSpaceId::new(8),
                ..LaneConfig::default()
            },
        ],
    )
    .unwrap();
    expanded.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&expanded.lane_catalog);
    for instruction in substitutions {
        let transaction = accepted(&key, instruction);
        let route = crate::queue::policy_route::PhysicalExecutionPolicyRoute::resolve(
            &expanded,
            view.world(),
            &transaction,
            1,
            0,
        )
        .unwrap();
        assert_eq!(
            route.decision(),
            RoutingDecision::new(LaneId::new(3), DataSpaceId::new(8))
        );
        assert_eq!(
            route.require_dataspace(RoutingDecision::new(
                LaneId::new(2),
                policy.physical_dataspace
            )),
            Err(crate::queue::policy_route::PhysicalPolicyRouteRejection::DataspaceMismatch)
        );
    }
}

#[test]
fn retail_monetary_requires_current_exact_definition_policy_and_activation() {
    let (mut state, nexus, key, policy) = fixture();
    let movement = instructions(&key, &policy)[2]
        .as_any()
        .downcast_ref::<RetailMonetaryMovementV1>()
        .unwrap()
        .clone();
    assert!(instruction_transaction_dataspace_target_needs_state(
        &movement
    ));
    assert_eq!(
        instruction_transaction_dataspace_target(&movement, Some(&nexus.dataspace_catalog), None),
        Err(RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "retail monetary routing requires current native policy state".into()
        })
    );
    let original_activation =
        crate::state::retail_daily_limit_state::activation_key(&policy.asset_definition_id);
    {
        let mut records = state.world.smart_contract_state_mut_for_testing().block();
        records.remove(original_activation.clone());
        records.commit();
    }
    assert_eq!(
        retail_monetary_dataspace_target_with_world(
            &movement,
            Some(&nexus.dataspace_catalog),
            &state.world.view(),
            Some(0)
        ),
        Err(RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "retail monetary native activation is invalid".into()
        })
    );
    state.world.smart_contract_state_mut_for_testing().insert(
        original_activation,
        norito::encode_canonical(
            &crate::state::retail_daily_limit_state::activation_for_policy(&policy, 0).unwrap(),
        )
        .unwrap(),
    );
    let mut substituted = policy.clone();
    substituted.physical_dataspace = DataSpaceId::new(8);
    state.world.smart_contract_state_mut_for_testing().insert(
        crate::state::retail_daily_limit_state::policy_key(
            &policy.asset_definition_id,
            policy.physical_dataspace,
        ),
        norito::encode_canonical(&substituted).unwrap(),
    );
    assert_eq!(
        retail_monetary_dataspace_target_with_world(
            &movement,
            Some(&nexus.dataspace_catalog),
            &state.world.view(),
            Some(0)
        ),
        Err(RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "retail monetary native policy is invalid".into()
        })
    );
    {
        let mut records = state.world.smart_contract_state_mut_for_testing().block();
        records.remove(crate::state::retail_daily_limit_state::policy_key(
            &policy.asset_definition_id,
            policy.physical_dataspace,
        ));
        records.commit();
    }
    assert_eq!(
        retail_monetary_dataspace_target_with_world(
            &movement,
            Some(&nexus.dataspace_catalog),
            &state.world.view(),
            Some(0)
        ),
        Err(RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "retail monetary native policy is absent".into()
        })
    );
    {
        let mut definitions = state.world.asset_definitions.block();
        definitions.remove(policy.asset_definition_id.clone());
        definitions.commit();
    }
    assert_eq!(
        retail_monetary_dataspace_target_with_world(
            &movement,
            Some(&nexus.dataspace_catalog),
            &state.world.view(),
            Some(0)
        ),
        Err(RoutingResolveError::OrdinaryRouteUnavailable {
            reason: "retail monetary definition is absent".into()
        })
    );
}
