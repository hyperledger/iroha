//! Original SNS and canonical account readers must defer unfinished routing decisions.
use super::*;
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn original_account_world() -> (
    crate::state::World,
    AccountId,
    AccountAlias,
    Vec<u8>,
    iroha_crypto::KeyPair,
) {
    let (owner, signer) = gen_account_in("routing_original_account");
    let catalog = DataSpaceCatalog::default();
    let alias = account_alias("holder@universal", &catalog);
    let mut world = crate::state::World::default();
    let (id, account) = Account::new(owner.clone())
        .with_label(Some(alias.clone()))
        .build(&owner)
        .into_key_value();
    world.accounts.insert(id, account);
    world.account_aliases.insert(alias.clone(), owner.clone());
    world
        .account_aliases_by_account
        .insert(owner.clone(), BTreeSet::from([alias.clone()]));
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(alias.clone(), owner.clone()),
    );
    let selector = crate::sns::selector_for_account_alias(&alias, &catalog).unwrap();
    let address = AccountAddress::from_account_id(&owner).unwrap();
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    let original = record.encode();
    world
        .smart_contract_state_mut_for_testing()
        .insert(crate::sns::record_storage_key(&selector), original.clone());
    (world, owner, alias, original, signer)
}

fn without_decode_allocation<T>(read: impl FnOnce() -> T) -> T {
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
        read,
    )
}

fn assert_original_sns_refusal<W: WorldReadOnly>(world: &W, alias: &AccountAlias) {
    let refused = without_decode_allocation(|| {
        crate::sns::resolve_active_account_alias(world, world.dataspace_catalog(), alias, 0)
    });
    assert!(
        matches!(refused, Err(crate::sns::SnsError::Deferred(ref reason))
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "{refused:?}"
    );
}

fn assert_route_deferred(result: Result<RoutingDecision, RoutingResolveError>) {
    assert!(
        matches!(result, Err(RoutingResolveError::Deferred(ref reason))
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "an unfinished original account read published a routing outcome: {result:?}"
    );
}

#[test]
fn original_account_target_refusal_never_selects_the_default_route() {
    // This is the supported original-World fallback, before its derived directory exists.
    let (world, owner, alias, original, _) = original_account_world();
    let view = world.view();
    assert!(view.account_scope_directory().get(&owner).is_none());
    assert_original_sns_refusal(&view, &alias);
    let catalog = DataSpaceCatalog::default();
    let lanes = catalog_with_lanes(&[LaneId::SINGLE]);
    let policy = LaneRoutingPolicy::default();
    let route = || {
        resolve_query_routing_decision_with_world(
            &policy,
            &lanes,
            &catalog,
            &owner,
            &view,
            Some(0),
            None,
        )
    };
    assert_eq!(route().unwrap(), RoutingDecision::default());
    let refused = without_decode_allocation(route);
    let key = crate::sns::record_storage_key(
        &crate::sns::selector_for_account_alias(&alias, &catalog).unwrap(),
    );
    assert_eq!(view.smart_contract_state().get(&key), Some(&original));
    assert_eq!(route().unwrap(), RoutingDecision::default());
    assert_route_deferred(refused);
}

#[test]
fn original_signed_account_matcher_refusal_is_not_a_mismatch_or_panic() {
    let (world, owner, alias, original, _) = original_account_world();
    let chain = CertifiedTestChain::start(TestChainConfig::new(world, 0)).unwrap();
    let view = chain.state().view();
    assert_eq!(view.height(), 1);
    assert!(view.world().account_scope_directory().get(&owner).is_some());
    assert_original_sns_refusal(view.world(), &alias);
    let policy = LaneRoutingPolicy {
        rules: vec![LaneRoutingRule {
            lane: LaneId::SINGLE,
            dataspace: Some(DataSpaceId::UNIVERSAL),
            matcher: LaneRoutingMatcher {
                account: Some("holder@universal".into()),
                instruction: None,
                description: None,
            },
        }],
        ..LaneRoutingPolicy::default()
    };
    let route = || {
        resolve_query_routing_decision(
            &policy,
            &view.nexus().lane_catalog,
            &view.nexus().dataspace_catalog,
            &owner,
            Some(&view),
        )
    };
    let expected = route().unwrap();
    let refused = catch_unwind(AssertUnwindSafe(|| without_decode_allocation(route)));
    let key = crate::sns::record_storage_key(
        &crate::sns::selector_for_account_alias(&alias, view.world().dataspace_catalog()).unwrap(),
    );
    assert_eq!(
        view.world().smart_contract_state().get(&key),
        Some(&original)
    );
    assert_eq!(route().unwrap(), expected);
    assert_route_deferred(
        refused.expect("account formatting must not panic on local read refusal"),
    );
}

#[test]
fn original_canonical_account_matcher_preserves_decode_refusal_and_retry() {
    let (owner, _) = gen_account_in("canonical_routing_original");
    let encoded = owner.to_string();
    let producer = without_decode_allocation(|| AccountAddress::parse_encoded(&encoded, None));
    assert!(
        matches!(
            producer,
            Err(
                iroha_data_model::account::address::AccountAddressError::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. }
                )
            )
        ),
        "{producer:?}"
    );
    let policy = LaneRoutingPolicy {
        rules: vec![LaneRoutingRule {
            lane: LaneId::SINGLE,
            dataspace: Some(DataSpaceId::UNIVERSAL),
            matcher: LaneRoutingMatcher {
                account: Some(encoded),
                instruction: None,
                description: None,
            },
        }],
        ..LaneRoutingPolicy::default()
    };
    let catalog = DataSpaceCatalog::default();
    let lanes = catalog_with_lanes(&[LaneId::SINGLE]);
    let route = || resolve_query_routing_decision(&policy, &lanes, &catalog, &owner, None);
    let expected = route().unwrap();
    let refused = catch_unwind(AssertUnwindSafe(|| without_decode_allocation(route)));
    assert_eq!(route().unwrap(), expected);
    assert_route_deferred(
        refused.expect("canonical account matching must return the read refusal"),
    );
    for malformed in ["", "not-an-encoded-account", "0x00"] {
        assert_eq!(
            without_decode_allocation(|| account_matches_literal_or_encoded(malformed, &owner)),
            Ok(false)
        );
    }
    let (foreign, _) = gen_account_in("different_canonical_routing_account");
    assert_eq!(
        account_matches_literal_or_encoded(&foreign.to_string(), &owner),
        Ok(false)
    );
}

#[test]
fn account_matcher_completed_negatives_and_directory_authority_are_unchanged() {
    let (mut world, owner, alias, original, _) = original_account_world();
    let catalog = DataSpaceCatalog::default();
    let key = crate::sns::record_storage_key(
        &crate::sns::selector_for_account_alias(&alias, &catalog).unwrap(),
    );
    let match_alias = |world: &crate::state::World| {
        account_matches_with_world("holder@universal", &owner, &catalog, &world.view(), Some(0))
    };
    assert_eq!(match_alias(&world), Ok(true));
    assert_eq!(
        account_matches_with_world("invalid", &owner, &catalog, &world.view(), Some(0)),
        Ok(false)
    );
    assert_eq!(
        account_matches_with_world(
            "holder@universal",
            &owner,
            &catalog,
            &world.view(),
            Some(u64::MAX)
        ),
        Ok(false)
    );
    let (other, _) = gen_account_in("foreign_router_binding");
    world.account_aliases.insert(alias.clone(), other);
    assert_eq!(match_alias(&world), Ok(false));
    world.account_aliases.insert(alias.clone(), owner.clone());
    assert_eq!(match_alias(&world), Ok(true));
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), vec![0xFF]);
    assert_eq!(
        match_alias(&world),
        Ok(false),
        "malformed original record remains a completed mismatch"
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), original.clone());
    assert_eq!(match_alias(&world), Ok(true));
    world.account_aliases = mv::storage::Storage::default();
    assert_eq!(
        match_alias(&world),
        Ok(false),
        "revoked index cannot resolve"
    );
    world.account_aliases.insert(alias.clone(), owner.clone());
    let chain = CertifiedTestChain::start(TestChainConfig::new(world, 0)).unwrap();
    let view = chain.state().view();
    assert!(view.world().account_scope_directory().get(&owner).is_some());
    assert_original_sns_refusal(view.world(), &alias);
    // The committed directory owns scope and does not need a second SNS decode.
    assert_eq!(
        without_decode_allocation(|| account_matches_alias_scope_with_world(
            "universal",
            &owner,
            &catalog,
            view.world(),
            Some(0),
        )),
        Ok(true)
    );
    assert_eq!(
        without_decode_allocation(|| account_dataspace_target(Some(view.world()), &owner, Some(0))),
        Ok(None)
    );
    assert_eq!(
        view.world().smart_contract_state().get(&key),
        Some(&original)
    );
}

#[test]
fn original_wildcard_and_instruction_matchers_preserve_refusal_and_short_circuit() {
    let (world, owner, alias, _, _) = original_account_world();
    let (sender, key) = gen_account_in("matcher_sender");
    let catalog = DataSpaceCatalog::default();
    let view = world.view();
    assert_original_sns_refusal(&view, &alias);
    assert_eq!(
        account_matches_with_world("*@universal", &owner, &catalog, &view, Some(0)),
        Ok(true)
    );
    let refused = without_decode_allocation(|| {
        account_matches_with_world("*@universal", &owner, &catalog, &view, Some(0))
    });
    assert_eq!(
        refused.unwrap_err().reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let definition = iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
        .parse::<AssetDefinitionId>()
        .unwrap();
    let asset_transfer = InstructionBox::from(Transfer::asset_quantity(
        AssetId::new(definition, sender.clone()),
        1_u32,
        owner.clone(),
    ));
    let tx = sample_transaction(&sender, key.private_key(), vec![asset_transfer.clone()]);
    assert_eq!(
        instructions_match_with_world("transfer@universal", &tx, &catalog, &view, Some(0)),
        Ok(true)
    );
    let refused = without_decode_allocation(|| {
        instructions_match_with_world("transfer@universal", &tx, &catalog, &view, Some(0))
    });
    assert_eq!(
        refused.unwrap_err().reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let pure_transfer = Transfer::domain(
        sender.clone(),
        DomainId::try_new("merchant", "universal").unwrap(),
        owner,
    );
    let tx = sample_transaction(
        &sender,
        key.private_key(),
        vec![pure_transfer.into(), asset_transfer],
    );
    assert_eq!(
        without_decode_allocation(|| instructions_match_with_world(
            "transfer@universal",
            &tx,
            &catalog,
            &view,
            Some(0)
        )),
        Ok(true),
        "first completed matching instruction prevents later reads"
    );
}

#[test]
fn fallible_rule_selection_keeps_first_match_and_skips_inapplicable_query_rules() {
    let (owner, _) = gen_account_in("first_rule_owner");
    let canonical = LaneRoutingRule {
        lane: LaneId::SINGLE,
        dataspace: None,
        matcher: LaneRoutingMatcher {
            account: Some(owner.to_string()),
            instruction: None,
            description: None,
        },
    };
    let catch_all = LaneRoutingRule {
        lane: LaneId::SINGLE,
        dataspace: None,
        matcher: LaneRoutingMatcher {
            account: None,
            instruction: None,
            description: None,
        },
    };
    let rules = vec![catch_all, canonical];
    let selected = without_decode_allocation(|| {
        first_matching_rule(&rules, |rule| query_rule_matches(rule, &owner, None))
    })
    .unwrap()
    .unwrap();
    assert!(std::ptr::eq(selected, &rules[0]));
    let mut instruction_only = rules[1].clone();
    instruction_only.matcher.instruction = Some("transfer".into());
    assert_eq!(
        without_decode_allocation(|| query_rule_matches(&instruction_only, &owner, None)),
        Ok(false)
    );
    assert!(
        without_decode_allocation(
            || first_matching_rule(&rules[1..], |rule| query_rule_matches(rule, &owner, None))
        )
        .is_err()
    );
}

#[test]
fn original_native_policy_account_matcher_retains_refusal_before_route_selection() {
    use iroha_data_model::sumeragi_lanes::{SumeragiLanePolicy, SumeragiLaneRoute};
    let (world, owner, alias, original, signer) = original_account_world();
    let mut policy = SumeragiLanePolicy::for_chain(
        iroha_data_model::parameter::SumeragiParameters::default(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.routes.push(SumeragiLaneRoute {
        lane: LaneId::SINGLE,
        account: Some("holder@universal".into()),
        instruction: None,
    });
    policy.validate().unwrap();
    let mut config = TestChainConfig::new(world, 0);
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            policy.clone().into_custom_parameter(),
        ));
    let chain = CertifiedTestChain::start(config).unwrap();
    let view = chain.state().view();
    let snapshot = crate::sumeragi::lanes::routing::RoutingSnapshot::of(&view)
        .expect("completed signed routing snapshot before matcher refusal");
    assert_eq!(snapshot.policy(), Some(&policy));
    let mut builder = TransactionBuilder::new(
        chain.state().network_id_ref().clone(),
        owner,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "original matcher".to_owned(),
    )]);
    builder.set_creation_time(core::time::Duration::from_millis(1));
    let signed = builder.sign(signer.private_key());
    let (_, time_source) = TimeSource::new_mock(core::time::Duration::from_millis(2));
    let tx = AcceptedTransaction::accept_with_time_source(
        signed,
        chain.state().network_id_ref(),
        core::time::Duration::from_secs(30),
        TransactionParameters::default(),
        &view.crypto(),
        &time_source,
    )
    .expect("canonical signature and original signed network admission");
    let inputs = snapshot.inputs(view.world());
    assert_eq!(inputs.route(&tx, 2).unwrap(), Some(LaneId::SINGLE));
    assert_original_sns_refusal(view.world(), &alias);
    let result = without_decode_allocation(|| inputs.route(&tx, 2));
    assert_eq!(
        result.unwrap_err().reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    let key = crate::sns::record_storage_key(
        &crate::sns::selector_for_account_alias(&alias, view.world().dataspace_catalog()).unwrap(),
    );
    assert_eq!(
        view.world().smart_contract_state().get(&key),
        Some(&original)
    );
    assert_eq!(inputs.route(&tx, 2).unwrap(), Some(LaneId::SINGLE));
}
