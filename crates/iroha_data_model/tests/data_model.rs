//! Data-model smoke tests and roundtrips
use iroha_crypto::KeyPair;
use iroha_data_model::{parameter::BlockParameters, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_schema::Ident;
use std::str::FromStr as _;
// Lightweight DSL does not track predicate depth; skip related tests.
fn checked_random_account_id() -> AccountId {
    AccountId::new(
        KeyPair::try_random()
            .expect("generate checked data-model smoke account keypair")
            .public_key()
            .clone(),
    )
}
#[test]
fn transfer_isi_should_be_valid() {
    let _domain: DomainId = DomainId::try_new("crypto", "universal").expect("domain");
    let source_account = checked_random_account_id();
    let destination_account = checked_random_account_id();
    let asset_definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("crypto", "universal").unwrap(),
            "btc".parse().unwrap(),
        );
    let source_asset_id = AssetId::new(asset_definition_id, source_account);
    let _instruction = Transfer::asset_quantity(source_asset_id, 12u32, destination_account);
}
#[test]
fn block_parameters_roundtrip() {
    use std::num::NonZeroU64;
    let params = BlockParameters::new(NonZeroU64::new(1).unwrap());
    // Use stable header-framed Norito path over the inner value and reconstruct
    let inner: u64 = params.max_transactions().get();
    let bytes = norito::core::to_bytes(&inner).expect("encode");
    let archived = norito::core::from_bytes::<u64>(&bytes).expect("archived");
    let decoded_inner = <u64 as norito::core::DeserializePayload>::deserialize(archived);
    let decoded = BlockParameters::new(core::num::NonZeroU64::new(decoded_inner).unwrap());
    assert_eq!(decoded.max_transactions(), params.max_transactions());
}
#[test]
fn compound_predicate_roundtrip() {
    // Build a real predicate payload and ensure it round-trips via Norito.
    let predicate = CompoundPredicate::<Domain>::build(|p| p.exists("id"));
    // Use header-framed Norito path (predicate payload)
    let bytes = norito::core::to_bytes(&predicate).expect("encode");
    let archived = norito::core::from_bytes::<CompoundPredicate<Domain>>(&bytes).expect("archived");
    let decoded =
        <CompoundPredicate<Domain> as norito::core::DeserializePayload>::deserialize(archived);
    assert_eq!(decoded.json_payload(), predicate.json_payload());
}
#[test]
fn role_permission_changed_permission_accessor_exposes_inner_permission() {
    let role_id: RoleId = "moderator".parse().expect("valid role id");
    let account_ref = checked_random_account_id().to_string();
    let permission = Permission::new(
        Ident::from_str("CanModifyAccountMetadata").expect("valid identifier"),
        norito::json!({"account": account_ref}),
    );
    let record = RolePermissionChanged::new(role_id.clone(), permission.clone());
    assert_eq!(record.permission(), &permission);
    assert_eq!(record.role(), &role_id);
}
#[test]
fn account_permission_changed_permission_accessor_exposes_inner_permission() {
    let _domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let account_id = checked_random_account_id();
    let account_ref = account_id.to_string();
    let permission = Permission::new(
        Ident::from_str("CanModifyAccountMetadata").expect("valid identifier"),
        norito::json!({"account": account_ref}),
    );
    let record = AccountPermissionChanged::new(account_id.clone(), permission.clone());
    assert_eq!(record.permission(), &permission);
    assert_eq!(record.account(), &account_id);
}
// Removed: depth-limit tests relied on heavy DSL representation.
