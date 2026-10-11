//! Runtime tests for canonical pointer values in durable Kotodama state.
use iroha_crypto::Hash as IrohaHash;
use iroha_data_model::prelude::*;
use iroha_model_base::name::Name;
use ivm::{
    IVM, PointerType,
    mock_wsv::{MockWorldStateView, WsvHost},
    validate_tlv_bytes,
};
use ivm_abi::state_value::StateValueKindV1;
use kotodama_lang::compiler::Compiler;
use std::str::FromStr;
mod common;
fn account_from_public_key(public_key: &str) -> AccountId {
    AccountId::new(public_key.parse().expect("public key must be valid"))
}
fn resolve_state_value(host: &WsvHost, base: &Name, key: i64) -> Option<Vec<u8>> {
    let key = common::encode_int_state_value(key);
    let expected_path = format!("{}/{}", base.as_ref(), hex::encode(key));
    host.wsv.sc_get(&expected_path)
}
#[test]
fn pointer_map_default_roundtrip() {
    const AUTHORITY_PUBLIC_KEY: &str =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
    let src = r#"
        seiyaku PointerFFI {
            state StateMap<int, AccountId> Owners;
            hajimari() {
                Owners[7] = context::authority();
            }
        }
    "#;
    let bytecode = Compiler::new()
        .compile_source(src)
        .expect("compile pointer map contract");
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&bytecode).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &bytecode, "hajimari");
    let wsv = MockWorldStateView::new();
    let authority = account_from_public_key(AUTHORITY_PUBLIC_KEY);
    let host = WsvHost::new_with_subject(wsv, authority);
    vm.set_host(host);
    vm.run().expect("execute init");
    let host_ref = vm.host_mut_any().expect("host access");
    let host = host_ref.downcast_ref::<WsvHost>().expect("wsv host");
    let base = Name::from_str("Owners").expect("valid state name");
    let stored = resolve_state_value(host, &base, 7).expect("state entry present");
    // Durable storage contains the raw schema-bound record payload. The active
    // pointer atom contains the original validated AccountId envelope.
    let inner_envelope = common::decode_pointer_state_value(&stored, StateValueKindV1::AccountId);
    let inner = validate_tlv_bytes(&inner_envelope).expect("inner TLV");
    assert_eq!(inner.type_id, PointerType::AccountId);
    let decoded_account: AccountId =
        norito::decode_from_bytes(inner.payload).expect("decode account id");
    let expected: AccountId = account_from_public_key(AUTHORITY_PUBLIC_KEY);
    assert_eq!(decoded_account, expected);
    // Ensure payload hash matches expected data (sanity check).
    let hash: [u8; 32] = IrohaHash::new(inner.payload).into();
    let hash_offset = 7 + inner.payload.len();
    assert!(
        inner_envelope.len() >= hash_offset + hash.len(),
        "pointer atom must contain the complete embedded envelope hash",
    );
    let stored_hash = &inner_envelope[hash_offset..hash_offset + hash.len()];
    assert_eq!(stored_hash, hash.as_ref());
}
#[test]
fn pointer_asset_state_storage_wraps_inner_pointer() {
    const ASSET_DEFINITION: &str = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let src = format!(
        r#"
        seiyaku PointerAssetStorage {{ permission WriteState;
            state StateMap<int, AssetDefinitionId> Assets;

            kotoage fn main() authorize(WriteState) {{
                Assets[7] = AssetDefinitionId::parse("{asset_definition}");
            }}
        }}
    "#,
        asset_definition = ASSET_DEFINITION,
    );
    let bytecode = Compiler::new()
        .compile_source(&src)
        .expect("compile asset storage contract");
    let asset: AssetDefinitionId = ASSET_DEFINITION.parse().expect("asset definition literal");
    let authority = account_from_public_key(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let host = WsvHost::new_with_subject(MockWorldStateView::new(), authority);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&bytecode).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &bytecode, "main");
    vm.run().expect("store asset pointer");
    let host_ref = vm.host_mut_any().expect("host access");
    let host = host_ref.downcast_ref::<WsvHost>().expect("wsv host");
    let base = Name::from_str("Assets").expect("valid state name");
    let stored = resolve_state_value(host, &base, 7).expect("state entry present");
    let inner_envelope =
        common::decode_pointer_state_value(&stored, StateValueKindV1::AssetDefinitionId);
    let inner = validate_tlv_bytes(&inner_envelope).expect("inner TLV");
    assert_eq!(inner.type_id, PointerType::AssetDefinitionId);
    let decoded_asset: AssetDefinitionId =
        norito::decode_from_bytes(inner.payload).expect("decode asset definition");
    assert_eq!(decoded_asset, asset);
}
