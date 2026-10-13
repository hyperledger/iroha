//! Tests for the ledger-backed SNS storage and lifecycle implementation.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Registrable,
    account::{
        Account, AccountAddress, AccountId,
        rekey::{AccountAlias, AccountAliasDomain},
    },
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasAutoRenewStateV1, AliasDataSpaceIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1,
        AliasQuoteGuardV1, AliasTargetV1, ResolvedAccountAliasV1, ResolvedDataSpaceV1,
    },
    asset::{AssetDefinition, AssetDefinitionId},
    block::SignedBlock,
    domain::Domain,
    isi::{InstructionBox, Register, alias_setup::EnsureAlias},
    nexus::{DataSpaceCatalog, DataSpaceMetadata},
    sns::{
        NameControllerV1, NameFrozenStateV1, NameRecordV1, NameSelectorV1, NameStatus,
        NameTombstoneStateV1,
    },
    transaction::TransactionBuilder,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
include!("../sns_core_tests.rs");
#[test]
fn checked_keypair_preserves_default_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
}
fn another_owner() -> AccountId {
    let keypair = KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519)
        .expect("derive alternate SNS fixture owner");
    AccountId::new(keypair.public_key().clone())
}
fn dataspace_catalog() -> DataSpaceCatalog {
    DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "banking".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        DataSpaceMetadata {
            id: DataSpaceId::new(10),
            alias: "paynet".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("catalog")
}
fn world_with_payment_asset(definition_id: AssetDefinitionId) -> World {
    let authority = owner();
    let domain_id = DomainId::try_new("issuer", "universal").expect("domain");
    let domain = Domain::new(domain_id).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let definition = AssetDefinition::numeric(
        definition_id,
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    World::with([domain], [account], [definition])
}
fn controller(owner: &AccountId) -> NameControllerV1 {
    let address = AccountAddress::from_account_id(owner).expect("should encode account address");
    NameControllerV1::account(&address)
}
fn default_payment(_owner: &AccountId) -> LeasePayment {
    LeasePayment {
        asset_id: iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        gross_amount: default_namespace_lease_price(),
        net_amount: default_namespace_lease_price(),
    }
}
fn dataspace_record(
    alias: &str,
    owner: &AccountId,
    expires_at_ms: u64,
    grace_expires_at_ms: u64,
    redemption_expires_at_ms: u64,
) -> (NameSelectorV1, NameRecordV1) {
    let selector = selector_for_dataspace_alias(alias).expect("selector");
    let address = AccountAddress::from_account_id(owner).expect("account address");
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        10,
        expires_at_ms,
        grace_expires_at_ms,
        redemption_expires_at_ms,
        Metadata::default(),
    );
    (selector, record)
}
fn world_with_dataspace_record(selector: &NameSelectorV1, record: &NameRecordV1) -> World {
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(selector), record.encode());
    world
}
#[test]
fn account_alias_selector_uses_canonical_literal() {
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("treasury".parse().expect("label"), DataSpaceId::new(7));
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    assert_eq!(selector.suffix_id, ACCOUNT_ALIAS_SUFFIX_ID);
    assert_eq!(selector.label, "treasury@banking");
}
#[test]
fn active_account_alias_selector_resolves_canonical_domainful_literal() {
    let catalog = dataspace_catalog();
    let alias = AccountAlias::new(
        "treasury".parse().expect("label"),
        Some(AccountAliasDomain::new("banka".parse().expect("domain"))),
        DataSpaceId::new(7),
    );
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    let owner = owner();
    let account = Account::new(owner.clone()).build(&owner);
    let mut world = World::with([], [account], []);
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        0,
        100,
        200,
        300,
        Metadata::default(),
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    world.account_aliases.insert(alias.clone(), owner.clone());
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(alias.clone(), owner.clone()),
    );
    assert_eq!(selector.label, "treasury@banka.banking");
    assert_eq!(
        active_account_alias_selector(&world.view(), &catalog, &alias, 50)
            .expect("active selector"),
        selector,
    );
    assert_eq!(
        (resolve_active_account_alias(&world.view(), &catalog, &alias, 50))
            .expect("completed fixture operation"),
        Some(owner)
    );
}
#[test]
fn active_account_alias_selector_resolves_dynamic_only_dataspace() {
    let catalog = DataSpaceCatalog::default();
    let dataspace = DataSpaceId::new(42);
    let alias = AccountAlias::domainless("treasury".parse().expect("label"), dataspace);
    assert!(
        selector_for_account_alias(&alias, &catalog).is_err(),
        "the bootstrap catalog must not know the dynamic-only dataspace"
    );
    let owner = owner();
    let dataspace_selector =
        selector_for_dataspace_alias("paynet").expect("dynamic dataspace selector");
    let mut metadata = Metadata::default();
    metadata.insert(
        SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        iroha_primitives::json::Json::new(dataspace.as_u64()),
    );
    let dataspace_record = NameRecordV1::new(
        dataspace_selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        0,
        100,
        200,
        300,
        metadata,
    );
    let mut world = World::default();
    world.smart_contract_state_mut_for_testing().insert(
        record_storage_key(&dataspace_selector),
        dataspace_record.encode(),
    );
    let selector = active_account_alias_selector(&world.view(), &catalog, &alias, 50)
        .expect("live dynamic dataspace mapping should build the selector");
    assert_eq!(selector.suffix_id, ACCOUNT_ALIAS_SUFFIX_ID);
    assert_eq!(selector.label, "treasury@paynet");
}
#[test]
fn account_alias_selector_rejects_malformed_reserved_separator_literals() {
    for literal in [
        "treasury#banka.banking",
        "treas$ury@banka.banking",
        "treasury@@banka.banking",
        "treasury@banka@banking",
        "treasury@banka.banking.extra",
    ] {
        assert!(
            selector_for_account_alias_literal(literal).is_err(),
            "malformed account-alias selector must be rejected: {literal}",
        );
    }
}
#[test]
fn account_alias_resolution_requires_active_lease_and_consistent_indexes() {
    let catalog = dataspace_catalog();
    let alias =
        AccountAlias::domainless("resolver".parse().expect("label"), DataSpaceId::UNIVERSAL);
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    let owner = owner();
    let other = another_owner();
    let account = Account::new(owner.clone()).build(&owner);
    let other_account = Account::new(other.clone()).build(&owner);
    let mut world = World::with([], [account, other_account], []);
    let mut record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        0,
        100,
        200,
        300,
        Metadata::default(),
    );
    let key = record_storage_key(&selector);
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), record.encode());
    world.account_aliases.insert(alias.clone(), owner.clone());
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(alias.clone(), owner.clone()),
    );
    assert_eq!(
        (resolve_active_account_alias(&world.view(), &catalog, &alias, 50))
            .expect("completed fixture operation"),
        Some(owner.clone())
    );
    record.status = NameStatus::Frozen(NameFrozenStateV1 {
        reason: "hold".to_owned(),
        until_ms: 90,
    });
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), record.encode());
    assert_eq!(
        (resolve_active_account_alias(&world.view(), &catalog, &alias, 50))
            .expect("completed fixture operation"),
        None
    );
    record.status = NameStatus::Active;
    record.expires_at_ms = 40;
    record.grace_expires_at_ms = 45;
    record.redemption_expires_at_ms = 50;
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), record.encode());
    assert_eq!(
        (resolve_active_account_alias(&world.view(), &catalog, &alias, 50))
            .expect("completed fixture operation"),
        None
    );
    record.status = NameStatus::Tombstoned(NameTombstoneStateV1 {
        reason: "revoked".to_owned(),
    });
    record.expires_at_ms = 100;
    record.grace_expires_at_ms = 200;
    record.redemption_expires_at_ms = 300;
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), record.encode());
    assert_eq!(
        (resolve_active_account_alias(&world.view(), &catalog, &alias, 50))
            .expect("completed fixture operation"),
        None
    );
    record.status = NameStatus::Active;
    world
        .smart_contract_state_mut_for_testing()
        .insert(key, record.encode());
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(alias.clone(), other),
    );
    assert_eq!(
        (resolve_active_account_alias(&world.view(), &catalog, &alias, 50))
            .expect("completed fixture operation"),
        None,
        "split binding indexes must fail closed"
    );
}

#[test]
fn account_alias_authentication_uses_stable_borrowed_catalog_and_original_counter() {
    let catalog = DataSpaceCatalog::default();
    let alias = AccountAlias::domainless(
        "authentication".parse().expect("canonical alias"),
        DataSpaceId::UNIVERSAL,
    );
    let selector = selector_for_account_alias(&alias, &catalog).unwrap();
    let owner = owner();
    let mut world = World::with([], [Account::new(owner.clone()).build(&owner)], []);
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        0,
        100,
        200,
        300,
        Metadata::default(),
    );
    let encoded = record.encode();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), encoded.clone());
    world.account_aliases.insert(alias.clone(), owner.clone());
    world.replace_account_rekey_record_for_testing(
        iroha_data_model::account::rekey::AccountRekeyRecord::new(alias.clone(), owner.clone()),
    );
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let pool = iroha_allocation::AllocationBudget::new(1024 * 1024);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(100_000, 128 * 1024, 100_000, 1024 * 1024, 32),
        &pool,
    )
    .unwrap();
    let result = state
        .try_with_authorization_view(&context, |view| {
            resolve_active_account_alias(
                view.world(),
                view.catalog(),
                &alias,
                view.ledger_time_ms(),
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(result, Some(owner));
    assert!(context.consumed_allocated_bytes() > 0);
    let refused = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(100_000, 128 * 1024, 100_000, 0, 32),
        &pool,
    )
    .unwrap();
    assert!(
        state
            .try_with_authorization_view(&refused, |view| {
                resolve_active_account_alias(
                    view.world(),
                    view.catalog(),
                    &alias,
                    view.ledger_time_ms(),
                )
            })
            .unwrap()
            .is_err(),
        "authentication cannot reset or replace the caller's exhausted counter"
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert!(
        decode_record_for_selector(&trailing, &selector).is_err(),
        "borrowing exact wire bytes must preserve trailing-byte refusal"
    );
}
#[test]
fn account_id_rekey_lineage_requires_typed_live_unambiguous_retired_history() {
    use iroha_data_model::account::rekey::{AccountRekeyRecord, AccountRekeyTransitionProvenance};
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("lineage".parse().expect("label"), DataSpaceId::UNIVERSAL);
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    let retired = checked_account_id();
    let active = checked_account_id();
    let unrelated = checked_account_id();
    let mut world = World::with(
        [],
        [
            Account::new(active.clone()).build(&active),
            Account::new(unrelated.clone()).build(&active),
        ],
        [],
    );
    let mut lease = NameRecordV1::new(
        selector.clone(),
        active.clone(),
        vec![controller(&active)],
        0,
        0,
        100,
        200,
        300,
        Metadata::default(),
    );
    let storage_key = record_storage_key(&selector);
    world
        .smart_contract_state_mut_for_testing()
        .insert(storage_key.clone(), lease.encode());
    world.account_aliases.insert(alias.clone(), active.clone());
    let canonical = AccountRekeyRecord::new(alias.clone(), retired.clone())
        .repoint_for_account_id_rekey(active.clone())
        .expect("canonical account-id rekey fixture");
    world.replace_account_rekey_record_for_testing(canonical.clone());
    assert_eq!(
        (resolve_active_account_id_rekey_lineage_for_alias(
            &world.view(),
            &catalog,
            &alias,
            &retired,
            50,
        ))
        .expect("completed fixture operation"),
        Some(active.clone())
    );
    assert_eq!(
        (resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50))
            .expect("completed fixture operation"),
        Some(active.clone())
    );
    assert_eq!(
        (resolve_active_account_id_rekey_lineage_for_alias(
            &world.view(),
            &catalog,
            &alias,
            &unrelated,
            50,
        ))
        .expect("completed fixture operation"),
        None,
        "an unrelated account must not join the lineage"
    );
    lease.expires_at_ms = 40;
    lease.grace_expires_at_ms = 45;
    lease.redemption_expires_at_ms = 50;
    world
        .smart_contract_state_mut_for_testing()
        .insert(storage_key.clone(), lease.encode());
    assert_eq!(
        (resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50))
            .expect("completed fixture operation"),
        None,
        "expired lineage lease must fail closed"
    );
    lease.status = NameStatus::Tombstoned(NameTombstoneStateV1 {
        reason: "revoked".to_owned(),
    });
    lease.expires_at_ms = 100;
    lease.grace_expires_at_ms = 200;
    lease.redemption_expires_at_ms = 300;
    world
        .smart_contract_state_mut_for_testing()
        .insert(storage_key.clone(), lease.encode());
    assert_eq!(
        (resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50))
            .expect("completed fixture operation"),
        None,
        "revoked lineage lease must fail closed"
    );
    lease.status = NameStatus::Active;
    world
        .smart_contract_state_mut_for_testing()
        .insert(storage_key.clone(), lease.encode());
    world.replace_account_rekey_record_for_testing(
        AccountRekeyRecord::new(alias.clone(), retired.clone())
            .reassign_alias_to_account(active.clone())
            .expect("alias reassignment fixture"),
    );
    assert_eq!(
        (resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50))
            .expect("completed fixture operation"),
        None,
        "ordinary alias reassignment must break controller lineage"
    );
    let mut malformed = canonical.clone();
    malformed.previous_account_ids.push(retired.clone());
    malformed
        .transition_provenance
        .push(AccountRekeyTransitionProvenance::AccountIdRekey);
    world.replace_account_rekey_record_for_testing(malformed);
    assert!(
        resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50).is_err(),
        "duplicate predecessor history must fail closed"
    );
    let mut cyclic = canonical.clone();
    cyclic.previous_account_ids.push(active.clone());
    cyclic
        .transition_provenance
        .push(AccountRekeyTransitionProvenance::AccountIdRekey);
    world.replace_account_rekey_record_for_testing(cyclic);
    assert!(
        resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50).is_err(),
        "active-id cycles must fail closed"
    );
    world.replace_account_rekey_record_for_testing(canonical);
    let second_alias =
        AccountAlias::domainless("ambiguous".parse().expect("label"), DataSpaceId::UNIVERSAL);
    let second_selector = selector_for_account_alias(&second_alias, &catalog).expect("selector");
    let second_lease = NameRecordV1::new(
        second_selector.clone(),
        unrelated.clone(),
        vec![controller(&unrelated)],
        0,
        0,
        100,
        200,
        300,
        Metadata::default(),
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&second_selector), second_lease.encode());
    world
        .account_aliases
        .insert(second_alias.clone(), unrelated.clone());
    world.replace_account_rekey_record_for_testing(
        AccountRekeyRecord::new(second_alias, retired.clone())
            .repoint_for_account_id_rekey(unrelated)
            .expect("ambiguous fixture transition"),
    );
    assert!(
        resolve_active_account_id_rekey_lineage(&world.view(), &catalog, &retired, 50).is_err(),
        "one retired predecessor cannot resolve to two active targets"
    );
}
#[test]
fn sns_namespace_from_path_accepts_account_alias_spelling_variants() {
    assert_eq!(
        SnsNamespace::from_path("account-alias").expect("hyphenated namespace"),
        SnsNamespace::AccountAlias
    );
    assert_eq!(
        SnsNamespace::from_path("account_alias").expect("underscored namespace"),
        SnsNamespace::AccountAlias
    );
}
#[test]
fn sns_namespace_from_path_rejects_unknown_value() {
    let err = SnsNamespace::from_path("mystery").expect_err("unknown path must fail");
    assert!(
        err.to_string().contains("unknown SNS namespace"),
        "unexpected error: {err}"
    );
}
#[test]
fn sns_namespace_from_suffix_id_rejects_unknown_value() {
    let err = SnsNamespace::from_suffix_id(0xFFFF).expect_err("unknown suffix id must fail");
    assert!(
        err.to_string().contains("unsupported SNS suffix id"),
        "unexpected error: {err}"
    );
}
#[test]
fn active_dataspace_owner_reads_from_world_storage() {
    let catalog = dataspace_catalog();
    let selector = selector_for_dataspace_alias("banking").expect("selector");
    let owner = another_owner();
    let address = AccountAddress::from_account_id(&owner).expect("account address");
    let mut record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    record.metadata.insert(
        SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        IrohaJson::new(7_u64),
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let view = world.view();
    assert_eq!(
        (active_dataspace_owner_by_id(&view, &catalog, DataSpaceId::new(7), 50))
            .expect("completed fixture operation"),
        Some(owner)
    );
}
#[test]
fn active_dataspace_id_rejects_conflicting_static_and_dynamic_mappings() {
    let catalog = dataspace_catalog();
    let selector = selector_for_dataspace_alias("banking").expect("selector");
    let owner = another_owner();
    let address = AccountAddress::from_account_id(&owner).expect("account address");
    let record = NameRecordV1::new(
        selector.clone(),
        owner,
        vec![NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let error = resolve_active_dataspace_id_by_alias(&world.view(), &catalog, "banking", 50);
    let error = error.expect_err("conflicting directories must fail closed");
    assert!(
        error
            .to_string()
            .contains(ALIAS_CATALOG_MAPPING_CONFLICT_CODE),
        "unexpected error: {error}"
    );
    let actual =
        (active_dataspace_id_by_alias(&world.view(), &catalog, "banking", 50)).unwrap_err();
    match (actual, error) {
        (SnsError::Conflict(actual), SnsError::Conflict(expected)) => assert_eq!(actual, expected),
        (actual, expected) => panic!("catalog conflict differs: {actual:?} != {expected:?}"),
    };
}
#[test]
fn active_dataspace_id_accepts_matching_static_and_dynamic_mappings() {
    let selector = selector_for_dataspace_alias("banking").expect("selector");
    let expected_id = DataSpaceId::from_hash(&selector.name_hash());
    let catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: expected_id,
        alias: "banking".to_owned(),
        description: None,
        fault_tolerance: 1,
    }])
    .expect("matching dataspace catalog");
    let owner = another_owner();
    let address = AccountAddress::from_account_id(&owner).expect("account address");
    let record = NameRecordV1::new(
        selector.clone(),
        owner,
        vec![NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    assert_eq!(
        resolve_active_dataspace_id_by_alias(&world.view(), &catalog, "banking", 50)
            .expect("matching directories"),
        expected_id
    );
}
#[test]
fn active_dataspace_id_accepts_explicit_dynamic_id_matching_static_catalog() {
    let catalog = dataspace_catalog();
    let selector = selector_for_dataspace_alias("banking").expect("selector");
    let owner = another_owner();
    let address = AccountAddress::from_account_id(&owner).expect("account address");
    let mut record = NameRecordV1::new(
        selector.clone(),
        owner,
        vec![NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    record.metadata.insert(
        SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        IrohaJson::new(7_u64),
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    assert_eq!(
        resolve_active_dataspace_id_by_alias(&world.view(), &catalog, "banking", 50)
            .expect("matching explicit mapping"),
        DataSpaceId::new(7)
    );
}
#[test]
fn resolve_active_dataspace_id_by_alias_rejects_malformed_dynamic_only_record() {
    let catalog = DataSpaceCatalog::default();
    let selector = selector_for_dataspace_alias("alpha").expect("selector");
    let storage_key = record_storage_key(&selector);
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(storage_key.clone(), vec![0xFF]);

    let error = resolve_active_dataspace_id_by_alias(&world.view(), &catalog, "alpha", 50)
        .expect_err("malformed authoritative bytes must not resolve as an absent alias");
    match error {
        SnsError::Internal(message) => {
            assert!(
                message.contains("failed to decode an SNS record"),
                "{message}"
            );
        }
        other => panic!("malformed authoritative bytes returned the wrong error: {other}"),
    }

    let other_selector = selector_for_dataspace_alias("beta").expect("other selector");
    let owner = another_owner();
    let mismatched_record = NameRecordV1::new(
        other_selector,
        owner.clone(),
        vec![controller(&owner)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(storage_key, mismatched_record.encode());

    let error = resolve_active_dataspace_id_by_alias(&world.view(), &catalog, "alpha", 50)
        .expect_err("mismatched authoritative identity must not resolve as absence");
    match error {
        SnsError::Internal(message) => {
            assert!(
                message.contains("SNS record identity mismatch"),
                "{message}"
            );
        }
        other => panic!("mismatched authoritative identity returned the wrong error: {other}"),
    }
}
#[test]
fn active_dataspace_id_derives_from_dynamic_sns_alias() {
    let catalog = dataspace_catalog();
    let selector = selector_for_dataspace_alias("alpha").expect("selector");
    let expected_id = DataSpaceId::from_hash(&selector.name_hash());
    let owner = another_owner();
    let address = AccountAddress::from_account_id(&owner).expect("account address");
    let record = NameRecordV1::new(
        selector.clone(),
        owner,
        vec![NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let view = world.view();
    assert_eq!(
        active_dataspace_id_by_alias(&view, &catalog, "alpha", 50).expect("valid active mapping"),
        Some(expected_id)
    );
    let metadata = active_dataspace_metadata_by_alias(&view, &catalog, "alpha", 50)
        .expect("valid metadata lookup")
        .expect("metadata");
    assert_eq!(metadata.id, expected_id);
    assert_eq!(metadata.alias, "alpha");
    assert_eq!(
        resolve_active_dataspace_alias_by_id(&view, &catalog, expected_id, 50)
            .expect("dynamic reverse mapping"),
        "alpha"
    );
}
mod active_dataspace_alias_tests {
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    include!("active_dataspace_alias_tests.rs");
}
#[test]
fn active_dataspace_alias_by_id_rejects_static_dynamic_name_collision() {
    let catalog = dataspace_catalog();
    let selector = selector_for_dataspace_alias("banking").expect("selector");
    let owner = another_owner();
    let address = AccountAddress::from_account_id(&owner).expect("account address");
    let conflicting_id = DataSpaceId::new(8);
    let mut record = NameRecordV1::new(
        selector.clone(),
        owner,
        vec![NameControllerV1::account(&address)],
        0,
        10,
        110,
        210,
        310,
        Metadata::default(),
    );
    record.metadata.insert(
        SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace id metadata key"),
        IrohaJson::new(conflicting_id.as_u64()),
    );
    let mut world = World::default();
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    for id in [DataSpaceId::new(7), conflicting_id] {
        let error = resolve_active_dataspace_alias_by_id(&world.view(), &catalog, id, 50)
            .expect_err("both sides of a mapping collision must fail closed");
        assert!(
            error
                .to_string()
                .contains(ALIAS_CATALOG_MAPPING_CONFLICT_CODE),
            "unexpected error for {id}: {error}"
        );
    }
}
#[test]
fn dataspace_id_for_sns_alias_treats_universal_as_reserved_case_insensitively() {
    assert_eq!(
        dataspace_id_for_sns_alias("universal"),
        Some(DataSpaceId::UNIVERSAL)
    );
    assert_eq!(
        dataspace_id_for_sns_alias(" Universal "),
        Some(DataSpaceId::UNIVERSAL)
    );
}
#[test]
fn dataspace_id_for_sns_alias_rejects_empty_or_invalid_aliases() {
    assert_eq!(dataspace_id_for_sns_alias(""), None);
    assert_eq!(dataspace_id_for_sns_alias("   "), None);
    assert_eq!(dataspace_id_for_sns_alias("not valid"), None);
}
#[test]
fn active_dataspace_id_returns_none_for_unregistered_dynamic_alias() {
    let catalog = dataspace_catalog();
    let world = World::default();
    assert_eq!(
        active_dataspace_id_by_alias(&world.view(), &catalog, "alpha", 50)
            .expect("completed absent mapping"),
        None
    );
    assert_eq!(
        (active_dataspace_metadata_by_alias(&world.view(), &catalog, "alpha", 50))
            .expect("completed fixture operation"),
        None
    );
    let error = resolve_active_dataspace_id_by_alias(&world.view(), &catalog, "alpha", 50)
        .expect_err("unknown mapping must fail");
    assert!(error.to_string().contains("unknown dataspace alias"));
}
#[test]
fn active_dataspace_id_ignores_expired_dynamic_alias() {
    let catalog = dataspace_catalog();
    let owner = another_owner();
    let (selector, record) = dataspace_record("alpha", &owner, 10, 20, 30);
    let world = world_with_dataspace_record(&selector, &record);
    assert_eq!(
        active_dataspace_id_by_alias(&world.view(), &catalog, "alpha", 10)
            .expect("completed absent mapping"),
        None
    );
    assert_eq!(
        (active_dataspace_owner_by_alias(&world.view(), "alpha", 25))
            .expect("completed fixture operation"),
        None
    );
}
#[test]
fn active_dataspace_id_ignores_frozen_or_tombstoned_dynamic_alias() {
    let catalog = dataspace_catalog();
    let owner = another_owner();
    let (frozen_selector, mut frozen_record) =
        dataspace_record("frozen-alpha", &owner, 100, 200, 300);
    frozen_record.status = NameStatus::Frozen(NameFrozenStateV1 {
        reason: "governance hold".to_owned(),
        until_ms: 90,
    });
    let frozen_world = world_with_dataspace_record(&frozen_selector, &frozen_record);
    assert_eq!(
        active_dataspace_id_by_alias(&frozen_world.view(), &catalog, "frozen-alpha", 50)
            .expect("completed absent mapping"),
        None
    );
    let (tombstoned_selector, mut tombstoned_record) =
        dataspace_record("retired-alpha", &owner, 100, 200, 300);
    tombstoned_record.status = NameStatus::Tombstoned(NameTombstoneStateV1 {
        reason: "retired".to_owned(),
    });
    let tombstoned_world = world_with_dataspace_record(&tombstoned_selector, &tombstoned_record);
    assert_eq!(
        active_dataspace_id_by_alias(&tombstoned_world.view(), &catalog, "retired-alpha", 50)
            .expect("completed absent mapping"),
        None
    );
}
#[test]
fn quote_account_alias_registration_uses_default_policy_price_and_term() {
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("treasury".parse().expect("label"), DataSpaceId::new(7));
    let owner = owner();
    let mut world = World::default();
    seed_default_namespace_policies(&mut world);
    let view = world.view();
    let quote = quote_account_alias_registration(&view, &catalog, &alias, &owner, 2, None, 100)
        .expect("registration quote");
    assert_eq!(quote.selector.label, "treasury@banking");
    assert_eq!(
        quote.payment_asset_id,
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
    );
    assert_eq!(quote.charge_amount, Quantity::one());
    assert_eq!(quote.expires_at_ms, 100 + years_to_ms(2));
    let policy = policy_by_id(&view, quote.selector.suffix_id)
        .expect("stored policy")
        .expect("existing policy");
    let client_price =
        iroha_data_model::sns::pricing::quote_lease_price(&policy, &quote.selector, 2, None)
            .expect("client and consensus share canonical pricing");
    assert_eq!(client_price.amount, quote.charge_amount);
    assert_eq!(client_price.pricing_class, quote.pricing_class);
    assert_eq!(
        client_price.payment_asset,
        quote.payment_asset_definition_id
    );
}
#[test]
fn current_namespace_policies_seed_directly_with_configured_asset() {
    let payment_asset_definition_id =
        AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc")
            .expect("deployment XOR asset id");
    let payment_asset_literal = payment_asset_definition_id.to_string();
    let mut world = World::default();
    seed_default_namespace_policies_for_payment_asset(&mut world, &payment_asset_literal);
    for namespace in [
        SnsNamespace::AccountAlias,
        SnsNamespace::Domain,
        SnsNamespace::Dataspace,
    ] {
        let key = policy_storage_key(namespace.suffix_id());
        let policy = world
            .smart_contract_state
            .view()
            .get(&key)
            .and_then(|bytes| SuffixPolicyV1::decode(&mut bytes.as_slice()).ok())
            .expect("namespace policy");
        assert_eq!(policy.payment_asset_id, payment_asset_literal);
        assert!(
            policy
                .pricing
                .iter()
                .all(|tier| tier.base_price.asset_id == payment_asset_literal)
        );
        assert_eq!(policy.policy_version, 1);
    }
}
#[test]
fn nexus_configuration_rejects_mismatched_policy_state_without_mutation() {
    let configured_elsewhere = "61CtjvNd9T3THAR65GsMVHr82Bjc";
    let mut world = World::default();
    seed_default_namespace_policies_for_payment_asset(&mut world, configured_elsewhere);
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let before = {
        let view = state.view();
        policy_by_id(view.world(), ACCOUNT_ALIAS_SUFFIX_ID)
            .expect("valid account-alias policy state")
            .expect("account-alias policy")
    };
    let error = state
        .set_nexus(iroha_config::parameters::actual::Nexus::default())
        .expect_err("Nexus configuration must not retarget persisted SNS policy state");
    assert!(
        error
            .to_string()
            .contains("does not match configured Nexus fee asset"),
        "{error}"
    );
    let after = {
        let view = state.view();
        policy_by_id(view.world(), ACCOUNT_ALIAS_SUFFIX_ID)
            .expect("valid account-alias policy state")
            .expect("account-alias policy")
    };
    assert_eq!(
        after, before,
        "rejected configuration must not mutate policy"
    );
}
#[test]
fn configured_fee_asset_quote_rejects_stale_policy_without_retargeting_state() {
    let payment_asset_definition_id =
        AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc")
            .expect("deployment XOR asset id");
    let payment_asset_literal = payment_asset_definition_id.to_string();
    let mut world = world_with_payment_asset(payment_asset_definition_id.clone());
    seed_default_namespace_policies(&mut world);
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("treasury".parse().expect("label"), DataSpaceId::new(7));
    let err = quote_account_alias_registration_with_configured_fee_asset(
        &world.view(),
        &catalog,
        &alias,
        &owner(),
        2,
        None,
        100,
        &payment_asset_literal,
    )
    .expect_err("read-only quote must not virtually retarget a stale policy");
    assert!(
        err.to_string()
            .contains("does not match configured Nexus fee asset"),
        "unexpected error: {err}"
    );
    let stored_policy = policy_by_id(&world.view(), ACCOUNT_ALIAS_SUFFIX_ID)
        .expect("valid stored policy")
        .expect("stored policy");
    assert_eq!(
        stored_policy.payment_asset_id,
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        "rejected read-only quotes must not mutate policy state"
    );
    let account_policy_key = policy_storage_key(ACCOUNT_ALIAS_SUFFIX_ID);
    let before = world
        .smart_contract_state
        .view()
        .get(&account_policy_key)
        .expect("account-alias policy")
        .clone();
    let error =
        ensure_default_namespace_policies_match_configured(&world.view(), &payment_asset_literal)
            .expect_err("stale persisted policy must reject configuration");
    assert!(
        error
            .to_string()
            .contains("does not match configured Nexus fee asset"),
        "{error}"
    );
    assert_eq!(
        world.smart_contract_state.view().get(&account_policy_key),
        Some(&before),
        "rejected initialization must leave persisted policy bytes unchanged"
    );
    let mut current_world = world_with_payment_asset(payment_asset_definition_id.clone());
    seed_default_namespace_policies_for_payment_asset(&mut current_world, &payment_asset_literal);
    let quote = quote_account_alias_registration_with_configured_fee_asset(
        &current_world.view(),
        &catalog,
        &alias,
        &owner(),
        2,
        None,
        100,
        &payment_asset_literal,
    )
    .expect("quote from explicitly initialized current state");
    assert_eq!(quote.payment_asset_id, payment_asset_literal);
    assert_eq!(
        quote.payment_asset_definition_id,
        payment_asset_definition_id
    );
}
#[test]
fn quote_account_alias_registration_rejects_existing_record() {
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("treasury".parse().expect("label"), DataSpaceId::new(7));
    let owner = owner();
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        1,
        5_000,
        5_000 + (30 * MS_PER_DAY),
        5_000 + (90 * MS_PER_DAY),
        Metadata::default(),
    );
    let mut world = World::default();
    seed_default_namespace_policies(&mut world);
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let view = world.view();
    let err = quote_account_alias_registration(&view, &catalog, &alias, &owner, 1, None, 100)
        .expect_err("existing registration must be rejected");
    assert!(
        err.to_string().contains("already registered"),
        "unexpected error: {err}"
    );
}
#[test]
fn quote_account_alias_renewal_extends_from_existing_expiry() {
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("merchant".parse().expect("label"), DataSpaceId::new(7));
    let owner = owner();
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        1,
        5_000,
        5_000 + (30 * MS_PER_DAY),
        5_000 + (90 * MS_PER_DAY),
        Metadata::default(),
    );
    let mut world = World::default();
    seed_default_namespace_policies(&mut world);
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let view = world.view();
    let quote =
        quote_account_alias_renewal(&view, &catalog, &alias, 3, 4_000).expect("renewal quote");
    assert_eq!(quote.selector, selector);
    assert_eq!(
        quote.charge_amount,
        "1.5".parse::<Quantity>().expect("canonical quantity")
    );
    assert_eq!(quote.expires_at_ms, 5_000 + years_to_ms(3));
}
#[test]
fn quote_account_alias_renewal_rejects_tombstoned_record() {
    let catalog = dataspace_catalog();
    let alias = AccountAlias::domainless("merchant".parse().expect("label"), DataSpaceId::new(7));
    let owner = owner();
    let selector = selector_for_account_alias(&alias, &catalog).expect("selector");
    let mut record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        1,
        5_000,
        5_000 + (30 * MS_PER_DAY),
        5_000 + (90 * MS_PER_DAY),
        Metadata::default(),
    );
    record.status = NameStatus::Tombstoned(NameTombstoneStateV1 {
        reason: "retired".to_owned(),
    });
    let mut world = World::default();
    seed_default_namespace_policies(&mut world);
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let view = world.view();
    let err = quote_account_alias_renewal(&view, &catalog, &alias, 1, 4_000)
        .expect_err("tombstoned registration must not renew");
    assert!(
        err.to_string().contains("tombstoned"),
        "unexpected error: {err}"
    );
}
#[test]
fn seed_default_namespace_policies_populates_fixed_suffixes() {
    let mut world = World::default();
    seed_default_namespace_policies(&mut world);
    let view = world.view();
    assert!(
        policy_by_id(&view, ACCOUNT_ALIAS_SUFFIX_ID)
            .expect("valid account-alias policy state")
            .is_some()
    );
    let domain_policy = policy_by_id(&view, DOMAIN_NAME_SUFFIX_ID)
        .expect("valid domain policy state")
        .expect("domain policy should be seeded");
    assert!(
        domain_policy
            .reserved_labels
            .iter()
            .any(|entry| entry.normalized_label == "treasury"),
        "default domain policy should keep the reserved treasury label"
    );
    assert!(
        policy_by_id(&view, DATASPACE_ALIAS_SUFFIX_ID)
            .expect("valid dataspace policy state")
            .is_some()
    );
}
#[test]
fn sns_decoders_reject_trailing_bytes_and_embedded_identity_mismatches() {
    let owner = owner();
    let selector =
        selector_for_namespace_literal(SnsNamespace::Domain, "strict.universal").expect("selector");
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    let record_key = record_storage_key(&selector);
    let mut world = World::default();
    let mut trailing_record = record.encode();
    trailing_record.push(0xA5);
    world
        .smart_contract_state
        .insert(record_key.clone(), trailing_record);
    assert!(record_by_selector(&world.view(), &selector).is_err());
    let active_owner_error = active_owner_by_selector(&world.view(), &selector, 0)
        .expect_err("active-owner lookup must surface malformed record state");
    assert!(
        matches!(active_owner_error, SnsError::Internal(_)),
        "malformed authoritative bytes must surface a storage failure: {active_owner_error}"
    );
    let err = record_or_not_found(&world.view(), &selector)
        .expect_err("trailing record bytes must fail closed");
    assert!(matches!(err, SnsError::Internal(_)), "{err}");
    let other_selector = selector_for_namespace_literal(SnsNamespace::Domain, "other.universal")
        .expect("other selector");
    let mut mismatched_record = record.clone();
    mismatched_record.selector = other_selector.clone();
    mismatched_record.name_hash = other_selector.name_hash();
    world
        .smart_contract_state
        .insert(record_key, mismatched_record.encode());
    assert!(record_by_selector(&world.view(), &selector).is_err());
    let err = record_or_not_found(&world.view(), &selector)
        .expect_err("embedded record identity must match its lookup selector");
    assert!(err.to_string().contains("identity mismatch"), "{err}");
    seed_default_namespace_policies(&mut world);
    let policy_key = policy_storage_key(DOMAIN_NAME_SUFFIX_ID);
    let policy = policy_by_id(&world.view(), DOMAIN_NAME_SUFFIX_ID)
        .expect("valid domain policy state")
        .expect("domain policy");
    let mut trailing_policy = policy.encode();
    trailing_policy.push(0x5A);
    world
        .smart_contract_state
        .insert(policy_key.clone(), trailing_policy.clone());
    assert!(policy_by_id(&world.view(), DOMAIN_NAME_SUFFIX_ID).is_err());
    let error = try_seed_default_namespace_policies(
        &mut world,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect_err("corrupt persisted policy must reject initialization");
    assert!(matches!(error, SnsError::Internal(_)), "{error}");
    assert_eq!(
        world.smart_contract_state.view().get(&policy_key),
        Some(&trailing_policy),
        "seeding must not overwrite corrupt policy evidence"
    );
    let mut mismatched_policy = policy;
    mismatched_policy.suffix_id = DATASPACE_ALIAS_SUFFIX_ID;
    mismatched_policy.suffix = ".dataspace".to_owned();
    world
        .smart_contract_state
        .insert(policy_key, mismatched_policy.encode());
    assert!(policy_by_id(&world.view(), DOMAIN_NAME_SUFFIX_ID).is_err());
    let err = policy_or_not_found(&world.view(), DOMAIN_NAME_SUFFIX_ID)
        .expect_err("embedded policy identity must match its storage suffix");
    assert!(err.to_string().contains("identity mismatch"), "{err}");
}
#[test]
fn state_initialization_rejects_non_current_account_alias_policy_without_mutation() {
    let steward = owner();
    let mut policy = default_namespace_policy(
        SnsNamespace::AccountAlias,
        &steward,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    );
    policy.pricing[0].label_regex = r"^[a-z0-9@.-]{3,255}$".to_owned();
    let mut world = World::default();
    let policy_key = policy_storage_key(ACCOUNT_ALIAS_SUFFIX_ID);
    let encoded = policy.encode();
    world
        .smart_contract_state_mut_for_testing()
        .insert(policy_key.clone(), encoded.clone());
    let error = State::try_new(
        crate::state::AllocationBudget::new(
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
        ),
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        #[cfg(feature = "telemetry")]
        crate::telemetry::StateTelemetry::default(),
    )
    .err()
    .expect("non-current SNS policy must reject State initialization");
    assert!(
        error
            .to_string()
            .contains("does not cover the current first-release label grammar"),
        "{error}"
    );
    let mut unchanged_world = World::default();
    unchanged_world
        .smart_contract_state_mut_for_testing()
        .insert(policy_key.clone(), encoded.clone());
    let error = try_seed_default_namespace_policies(
        &mut unchanged_world,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect_err("non-current SNS policy must fail closed");
    assert!(error.to_string().contains("first-release label grammar"));
    assert_eq!(
        unchanged_world.smart_contract_state.view().get(&policy_key),
        Some(&encoded),
        "rejected policy initialization must not rewrite authoritative state"
    );
}
#[test]
fn seed_genesis_alias_records_covers_domains_and_account_labels() {
    let genesis_key = checked_keypair();
    let genesis_account = AccountId::new(genesis_key.public_key().clone());
    let domain_id: DomainId = DomainId::try_new("cbuae", "universal").expect("domain");
    let account_id = checked_account_id();
    let label = AccountAlias::new(
        "gas".parse().expect("label"),
        Some(AccountAliasDomain::new(domain_id.name().clone())),
        DataSpaceId::UNIVERSAL,
    );
    let bound_alias = AccountAlias::new(
        "settlement".parse().expect("label"),
        Some(AccountAliasDomain::new(domain_id.name().clone())),
        DataSpaceId::UNIVERSAL,
    );
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: DataSpaceId::new(4),
            alias: "cbuae".to_owned(),
            fault_tolerance: 1,
            ..DataSpaceMetadata::default()
        },
    ])
    .expect("dataspace catalog");
    let primary_alias = AccountAlias::new(
        "ops".parse().expect("label"),
        Some(AccountAliasDomain::new(domain_id.name().clone())),
        DataSpaceId::UNIVERSAL,
    );
    let payment_asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("assets", "universal").expect("asset domain"),
        "xor".parse().expect("asset name"),
    );
    let ensure_alias = |literal: &str, target_account: AccountId, role| {
        EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: ResolvedAccountAliasV1::new(
                    literal.parse().expect("resolved account alias"),
                    DataSpaceId::UNIVERSAL,
                ),
                target_account,
                provision: AccountProvisionV1::Existing,
                role,
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: 1,
                expected_payment_asset: payment_asset.clone(),
                max_amount: Quantity::zero(),
                valid_until_ms: u64::MAX,
            },
        )
    };
    let ensure_dataspace = EnsureAlias::new(
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(
                "cbuae".parse().expect("dataspace name"),
                DataSpaceId::new(4),
            ),
            owner: genesis_account.clone(),
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: 1,
            expected_payment_asset: payment_asset.clone(),
            max_amount: Quantity::zero(),
            valid_until_ms: u64::MAX,
        },
    );
    let tx = TransactionBuilder::new_genesis(
        genesis_account.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Batch(
        [
            InstructionBox::from(ensure_dataspace.clone()),
            InstructionBox::from(Register::domain(Domain::new(domain_id.clone()))),
            InstructionBox::from(Register::account(
                Account::new(account_id.clone()).with_label(Some(label.clone())),
            )),
            InstructionBox::from(ensure_alias(
                "settlement@cbuae.universal",
                account_id.clone(),
                AccountAliasRoleV1::Additional,
            )),
            InstructionBox::from(ensure_alias(
                "ops@cbuae.universal",
                genesis_account.clone(),
                AccountAliasRoleV1::Primary,
            )),
        ]
        .into_iter()
        .map(iroha_data_model::transaction::ExecutableBatchItem::Instruction)
        .collect::<Vec<_>>()
        .into(),
    ))
    .sign(genesis_key.private_key());
    let block = SignedBlock::genesis(vec![tx], genesis_key.private_key(), None, None);
    let bootstrap_authority = block
        .external_transactions()
        .next()
        .expect("genesis transaction")
        .authority()
        .clone();
    let mut world = World::default();
    seed_genesis_alias_records(&mut world, &block, &dataspace_catalog);
    let view = world.view();
    let domain_selector = selector_for_domain(&domain_id).expect("selector");
    let dataspace_selector = selector_for_dataspace_alias("cbuae").expect("selector");
    let label_selector = selector_for_account_alias(&label, &dataspace_catalog).expect("selector");
    let bound_selector =
        selector_for_account_alias(&bound_alias, &dataspace_catalog).expect("selector");
    let relabel_selector =
        selector_for_account_alias(&primary_alias, &dataspace_catalog).expect("selector");
    assert!(
        record_by_selector(&view, &domain_selector)
            .expect("valid genesis domain lease state")
            .is_some(),
        "genesis domain names must be leased before validation"
    );
    assert_eq!(
        record_by_selector(&view, &dataspace_selector)
            .expect("valid declarative dataspace lease state")
            .expect("declarative dataspace aliases must seed leases")
            .metadata,
        crate::alias_setup::alias_registration_metadata(&ensure_dataspace.intent.target())
            .expect("dataspace setup metadata"),
        "genesis dataspace leases must retain their immutable text-to-ID metadata"
    );
    assert_eq!(
        record_by_selector(&view, &label_selector)
            .expect("valid genesis account-label lease state")
            .expect("genesis account labels must be leased before validation")
            .owner,
        account_id,
        "genesis account-label leases must be owned by the registered target account"
    );
    assert_eq!(
        record_by_selector(&view, &bound_selector)
            .expect("valid declarative account-alias lease state")
            .expect("declarative account aliases must seed leases")
            .owner,
        account_id,
        "genesis bound-alias leases must be owned by the exact target account"
    );
    assert_eq!(
        record_by_selector(&view, &relabel_selector)
            .expect("valid declarative primary-alias lease state")
            .expect("declarative primary aliases must also seed leases")
            .owner,
        genesis_account,
        "genesis primary-alias leases must be owned by the exact target account"
    );
    let permissions = world
        .account_permissions
        .view()
        .get(&bootstrap_authority)
        .cloned()
        .expect("genesis authority permissions");
    assert!(
        permissions.contains(&Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(label.dataspace),
        })),
        "genesis authority must be able to manage the alias dataspace used at genesis"
    );
    assert!(
        permissions.contains(&Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain_id.clone()),
        })),
        "genesis authority must be able to manage the alias domain used at genesis"
    );
}
#[test]
fn register_name_persists_account_alias_record_in_state() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = another_owner();
    let record = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
                    label: "treasury@banking".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("register name");
    let view = state.view();
    let fetched = record_by_selector(view.world(), &record.selector)
        .expect("valid stored record state")
        .expect("stored record");
    assert_eq!(fetched.owner, owner);
    assert_eq!(fetched.selector.label, "treasury@banking");
}
#[test]
fn register_name_rejects_duplicate_domain_registration() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "duplicate.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("first registration");
    let err = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "duplicate.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect_err("duplicate registration must fail");
    assert!(
        err.to_string().contains("already registered"),
        "unexpected error: {err}"
    );
}
#[test]
fn register_name_accepts_underscore_account_alias_labels() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    let record = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
                    label: "pk_gov_pharmacy@paynet".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("register underscore account alias name");
    assert_eq!(record.selector.label, "pk_gov_pharmacy@paynet");
    assert_eq!(record.pricing_class, 0);
}
#[test]
fn sns_state_block_does_not_advance_transaction_height() {
    use iroha_data_model::block::BlockHeader;
    use nonzero_ext::nonzero;
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    assert_eq!(state.transactions_latest_height_for_testing(), 0);
    apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
                    label: "ops@banking".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("register name");
    assert_eq!(
        state.transactions_latest_height_for_testing(),
        0,
        "SNS state-only mutations must not advance committed transaction height"
    );
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    {
        let tx = block.transaction();
        tx.apply();
    }
    block
        .commit_empty_block_for_testing()
        .expect("real block commit after SNS mutation should succeed");
    assert_eq!(state.transactions_latest_height_for_testing(), 1);
}
#[test]
fn sns_state_block_uses_wall_clock_lifecycle_time() {
    use std::time::SystemTime;
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    let before_ms = u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_millis(),
    )
    .expect("fixture value fits u64");
    let record = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "soraswap.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("register name");
    assert!(
        record.registered_at_ms >= before_ms.saturating_sub(1_000),
        "SNS lifecycle timestamps should track wall clock time"
    );
    assert!(
        record.expires_at_ms > before_ms + MS_PER_DAY,
        "one-year registration should not appear expired immediately"
    );
}
#[test]
fn register_domain_name_rejects_bare_domain_literal() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    let err = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "soraswap".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect_err("bare domain labels must be rejected");
    assert!(
        err.to_string().contains("domain.dataspace"),
        "unexpected error: {err}"
    );
}
#[test]
fn register_domain_name_reserved_label_requires_steward() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = another_owner();
    let steward = fixtures::steward_account();
    let err = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "treasury.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect_err("non-steward should not claim reserved domain label");
    assert!(
        err.to_string().contains("reserved"),
        "unexpected error: {err}"
    );
    let record = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "treasury.universal".to_owned(),
                },
                owner: steward.clone(),
                controllers: vec![controller(&steward)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&steward),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("steward should keep reserved domain label");
    assert_eq!(record.owner, steward);
}
#[test]
fn find_active_reserved_domain_label_matches_label_key() {
    let steward = fixtures::steward_account();
    let policy = default_namespace_policy(
        SnsNamespace::Domain,
        &steward,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    );
    let selector =
        NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, "treasury.universal").expect("selector");
    let reserved = find_active_reserved_label(SnsNamespace::Domain, &policy, &selector, 0)
        .expect("domain label reservation should match the label key");
    assert_eq!(reserved.normalized_label, "treasury");
}
#[test]
fn find_active_reserved_domain_label_matches_fully_qualified_literal() {
    let steward = fixtures::steward_account();
    let mut policy = default_namespace_policy(
        SnsNamespace::Domain,
        &steward,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    );
    policy.reserved_labels = vec![ReservedNameV1 {
        normalized_label: "ops.universal".to_owned(),
        assigned_to: Some(steward),
        release_at_ms: None,
        note: "Explicit fully qualified reservation".to_owned(),
    }];
    let selector = NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, "ops.universal").expect("selector");
    let reserved = find_active_reserved_label(SnsNamespace::Domain, &policy, &selector, 0)
        .expect("fully qualified domain literal should match directly");
    assert_eq!(reserved.normalized_label, "ops.universal");
}
#[test]
fn find_active_reserved_domain_label_honors_release_boundary() {
    let steward = fixtures::steward_account();
    let mut policy = default_namespace_policy(
        SnsNamespace::Domain,
        &steward,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    );
    policy.reserved_labels = vec![ReservedNameV1 {
        normalized_label: "ops".to_owned(),
        assigned_to: Some(steward),
        release_at_ms: Some(10),
        note: "Scheduled release".to_owned(),
    }];
    let selector = NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, "ops.universal").expect("selector");
    assert!(
        find_active_reserved_label(SnsNamespace::Domain, &policy, &selector, 9).is_some(),
        "reservation should still be active before the release timestamp"
    );
    assert!(
        find_active_reserved_label(SnsNamespace::Domain, &policy, &selector, 10).is_none(),
        "reservation should stop matching at the release timestamp"
    );
}
#[test]
fn enforce_reserved_label_assignment_rejects_unassigned_domain_label() {
    let steward = fixtures::steward_account();
    let mut policy = default_namespace_policy(
        SnsNamespace::Domain,
        &steward,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    );
    policy.reserved_labels = vec![ReservedNameV1 {
        normalized_label: "custody".to_owned(),
        assigned_to: None,
        release_at_ms: None,
        note: "Unassigned reserved label".to_owned(),
    }];
    let owner = another_owner();
    let selector =
        NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, "custody.universal").expect("selector");
    let err =
        enforce_reserved_label_assignment(SnsNamespace::Domain, &policy, &selector, &owner, 0)
            .expect_err("unassigned reserved labels must reject registration");
    assert!(
        err.to_string().contains("label `custody` is reserved"),
        "unexpected error: {err}"
    );
}
#[test]
fn enforce_reserved_label_assignment_allows_matching_assignee() {
    let steward = fixtures::steward_account();
    let policy = default_namespace_policy(
        SnsNamespace::Domain,
        &steward,
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    );
    let selector =
        NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, "treasury.universal").expect("selector");
    enforce_reserved_label_assignment(SnsNamespace::Domain, &policy, &selector, &steward, 0)
        .expect("matching assignee should be allowed");
}
#[test]
fn register_domain_name_allows_released_reserved_label() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let steward = fixtures::steward_account();
    let mut policy = {
        let view = state.view();
        policy_by_id(view.world(), DOMAIN_NAME_SUFFIX_ID)
            .expect("valid seeded domain policy state")
            .expect("seeded domain policy")
    };
    policy.reserved_labels = vec![ReservedNameV1 {
        normalized_label: "treasury".to_owned(),
        assigned_to: Some(steward),
        release_at_ms: Some(0),
        note: "Released reservation".to_owned(),
    }];
    state
        .world
        .smart_contract_state
        .insert(policy_storage_key(DOMAIN_NAME_SUFFIX_ID), policy.encode());
    let owner = another_owner();
    let record = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "treasury.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("released reserved labels should allow registration");
    assert_eq!(record.owner, owner);
}
#[test]
fn selector_for_namespace_literal_canonicalizes_domain_literal() {
    let selector = selector_for_namespace_literal(SnsNamespace::Domain, "TreAsury.Universal")
        .expect("domain selector");
    assert_eq!(selector.normalized_label(), "treasury.universal");
}
#[test]
fn selector_for_namespace_literal_canonicalizes_account_alias_literal() {
    let selector = selector_for_namespace_literal(SnsNamespace::AccountAlias, "Treasury@Banking")
        .expect("account alias selector");
    assert_eq!(selector.normalized_label(), "treasury@banking");
}
#[test]
fn account_alias_registration_lookup_supports_private_dataspace_without_catalog() {
    assert!(DataSpaceCatalog::default().by_alias("dpn").is_none());
    let selector = selector_for_namespace_literal(SnsNamespace::AccountAlias, "Admin@Dpn")
        .expect("canonical private alias selector");
    assert_eq!(selector.label, "admin@dpn");
    let owner = owner();
    let record = NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![controller(&owner)],
        0,
        0,
        100,
        200,
        300,
        Metadata::default(),
    );
    let mut world = World::default();
    let SnsError::RegistrationNotFound { suffix_id, label } =
        (get_name_record(&world.view(), SnsNamespace::AccountAlias, "admin@dpn", 50)).unwrap_err()
    else {
        panic!("expected exact absent registration");
    };
    assert_eq!(suffix_id, ACCOUNT_ALIAS_SUFFIX_ID);
    assert_eq!(label, "admin@dpn");
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    assert_eq!(
        get_name_record(&world.view(), SnsNamespace::AccountAlias, "Admin@Dpn", 50)
            .expect("private SNS account registration"),
        record,
    );
    let mut malformed = record.encode();
    malformed.push(0);
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), malformed);
    assert!(matches!(
        get_name_record(&world.view(), SnsNamespace::AccountAlias, "admin@dpn", 50),
        Err(SnsError::Internal(_)),
    ));
}
#[test]
fn selector_for_namespace_literal_canonicalizes_dataspace_literal() {
    let selector = selector_for_namespace_literal(SnsNamespace::Dataspace, "Banking")
        .expect("dataspace selector");
    assert_eq!(selector.normalized_label(), "banking");
}
#[test]
fn selector_for_namespace_literal_rejects_bare_domain_literal() {
    let err = selector_for_namespace_literal(SnsNamespace::Domain, "treasury")
        .expect_err("bare domain literal must fail");
    assert!(
        err.to_string().contains("domain.dataspace"),
        "unexpected error: {err}"
    );
}
#[test]
fn reserved_label_key_extracts_account_alias_local_label() {
    let selector = NameSelectorV1 {
        version: NameSelectorV1::VERSION,
        suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
        label: "treasury@banking".to_owned(),
    };
    assert_eq!(
        reserved_label_key(SnsNamespace::AccountAlias, &selector),
        "treasury"
    );
}
#[test]
fn reserved_label_key_keeps_dataspace_literal() {
    let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, "banking").expect("selector");
    assert_eq!(
        reserved_label_key(SnsNamespace::Dataspace, &selector),
        "banking"
    );
}
#[test]
fn register_name_rejects_unknown_suffix_id() {
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let owner = owner();
    let err = apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: 0xFFFF,
                    label: "mystery".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect_err("unknown suffix ids must be rejected");
    assert!(
        err.to_string().contains("unsupported SNS suffix id"),
        "unexpected error: {err}"
    );
}
#[test]
fn set_name_lease_expiry_rejects_past_timestamp() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "leasepast.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("register name");
    let err = apply_with_state_block(&state, |tx| {
        set_name_lease_expiry(tx, SnsNamespace::Domain, "leasepast.universal", 0)
    })
    .expect_err("past expiry must fail");
    assert!(
        err.to_string().contains("lease_expiry_ms must be greater"),
        "unexpected error: {err}"
    );
}
#[test]
fn set_name_lease_expiry_updates_lifecycle_windows() {
    let mut state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.set_dataspace_catalog_for_testing(dataspace_catalog());
    let owner = owner();
    apply_with_state_block(&state, |tx| {
        register_name(
            tx,
            RegisterNameInput {
                selector: NameSelectorV1 {
                    version: NameSelectorV1::VERSION,
                    suffix_id: DOMAIN_NAME_SUFFIX_ID,
                    label: "leasefuture.universal".to_owned(),
                },
                owner: owner.clone(),
                controllers: vec![controller(&owner)],
                term_years: 1,
                pricing_class_hint: None,
                payment: default_payment(&owner),
                metadata: Metadata::default(),
            },
        )
    })
    .expect("register name");
    let future_expiry_ms = u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_millis(),
    )
    .expect("fixture value fits u64")
        + 60_000;
    let record = apply_with_state_block(&state, |tx| {
        set_name_lease_expiry(
            tx,
            SnsNamespace::Domain,
            "leasefuture.universal",
            future_expiry_ms,
        )
    })
    .expect("lease expiry update");
    assert_eq!(record.expires_at_ms, future_expiry_ms);
    assert_eq!(
        record.grace_expires_at_ms,
        future_expiry_ms + 30 * MS_PER_DAY
    );
    assert_eq!(
        record.redemption_expires_at_ms,
        future_expiry_ms + 90 * MS_PER_DAY
    );
}
#[test]
fn reserved_universal_dataspace_selector_is_immutable() {
    let selector =
        selector_for_dataspace_alias(RESERVED_UNIVERSAL_DATASPACE_ALIAS).expect("selector");
    let err = ensure_selector_is_mutable(&selector)
        .expect_err("reserved universal selector must reject every mutation path");
    assert!(
        err.to_string().contains("immutable"),
        "unexpected error: {err}"
    );
}
#[test]
fn get_name_record_refreshes_expired_lifecycle() {
    let mut world = World::default();
    let selector =
        selector_for_domain(&DomainId::try_new("trade", "universal").expect("domain id"))
            .expect("selector");
    let owner = owner();
    let record = NameRecordV1::new(
        selector.clone(),
        owner,
        vec![controller(&another_owner())],
        0,
        0,
        5,
        10,
        15,
        Metadata::default(),
    );
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), record.encode());
    let view = world.view();
    let fetched =
        get_name_record(&view, SnsNamespace::Domain, "trade.universal", 11).expect("fetch record");
    assert!(matches!(fetched.status, NameStatus::Redemption));
}

#[test]
fn registration_absence_is_distinct_from_policy_and_malformed_state() {
    let mut world = World::default();
    let selector = selector_for_dataspace_alias("dpn").expect("selector");
    let SnsError::RegistrationNotFound { suffix_id, label } =
        (get_name_record_by_selector(&world.view(), &selector, 0)).unwrap_err()
    else {
        panic!("expected exact absent registration");
    };
    assert_eq!(suffix_id, selector.suffix_id);
    assert_eq!(label, selector.label);
    assert!(matches!(
        policy_or_not_found(&world.view(), u16::MAX),
        Err(SnsError::NotFound(_))
    ));
    world
        .smart_contract_state_mut_for_testing()
        .insert(record_storage_key(&selector), vec![0xff]);
    assert!(matches!(
        get_name_record_by_selector(&world.view(), &selector, 0),
        Err(SnsError::Internal(_))
    ));
}
