//! Kotodama DEX demo: compile and run a simple XYK pool on IVM.
use iroha_crypto::Hash;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity, numeric_abi::QuantityValueV1};
use ivm::{
    AccountId, AssetDefinitionId, IVM, MockWorldStateView, PermissionToken, PointerType,
    ProgramMetadata, mock_wsv::WsvHost,
};
use ivm_abi::arguments::encode_argument_record_from_json;
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use std::collections::BTreeMap;
fn fixture_account(hex_public_key: &str) -> AccountId {
    AccountId::new(hex_public_key.parse().expect("public key"))
}
fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("argument record length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    out
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Compile the Kotodama sample to IVM bytecode
    let src = include_str!("../../kotodama_lang/src/samples/dex_simple.ko");
    let compiler = KotodamaCompiler::new();
    let bytecode = compiler.compile_source(src).expect("compile dex_simple");
    let metadata = ProgramMetadata::parse(&bytecode).expect("parse dex_simple metadata");
    let swap = metadata
        .contract_interface
        .as_ref()
        .expect("dex_simple contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "swap")
        .expect("swap entrypoint descriptor");
    let entrypoint_pc =
        u64::try_from(metadata.prefix_len()).expect("program prefix fits u64") + swap.entry_pc;
    // 2) Prepare a tiny world with Alice (trader), Pool account, and two assets
    let alice =
        fixture_account("ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03");
    let pool =
        fixture_account("ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4");
    let asset_a: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "usdc".parse()?,
        );
    let asset_b: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "eth".parse()?,
        );
    // Initial balances: Alice has 1_000 USDC, pool has 997 USDC and 100 ETH.
    // These reserves make the post-fee share exactly 0.5, so the mock ledger's
    // scale-zero quantity policy can apply the quoted output without rounding.
    let wsv = MockWorldStateView::with_balances(&[
        ((alice.clone(), asset_a.clone()), Quantity::from(1_000_u64)),
        ((pool.clone(), asset_a.clone()), Quantity::from(997_u64)),
        ((pool.clone(), asset_b.clone()), Quantity::from(100_u64)),
    ]);
    let mut wsv = wsv;
    // Grant permissions for caller (Alice) to transfer these assets
    wsv.grant_permission(&alice, PermissionToken::TransferAsset(asset_a.clone()));
    wsv.grant_permission(&alice, PermissionToken::TransferAsset(asset_b.clone()));
    wsv.grant_permission(&alice, PermissionToken::ReadAccountAssets(alice.clone()));
    wsv.grant_permission(&alice, PermissionToken::ReadAccountAssets(pool.clone()));
    let alice_subject = alice.clone();
    // 3) Encode the Torii boundary payload as the schema-bound V1 argument record.
    let amount_in = 1_000_u64;
    let arguments = Json::from(norito::json!({
        "trader": (alice.to_string()),
        "pool_account": (pool.to_string()),
        "input_asset": (asset_a.canonical_address()),
        "output_asset": (asset_b.canonical_address()),
        "amount_in": (amount_in.to_string()),
        "reserve_in": "997",
        "reserve_out": "100",
    }));
    let schema = swap
        .argument_schema
        .as_ref()
        .expect("swap entrypoint argument schema");
    let record = encode_argument_record_from_json(schema, &arguments)
        .expect("encode canonical swap argument record");
    let input_name: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key is a Name");
    let host =
        WsvHost::new_with_subject(wsv, alice_subject).with_public_inputs(BTreeMap::from([(
            input_name,
            tlv(PointerType::NoritoBytes, &record),
        )]));
    // 4) Create the VM, attach the host, and select the public wrapper.
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&bytecode).expect("load program");
    vm.set_program_counter(entrypoint_pc)
        .expect("select swap entrypoint");
    // 5) Run the program and decode the pointer-backed quantity in r10.
    vm.run().expect("run VM");
    let result = vm
        .validate_tlv(vm.register(10))
        .expect("swap returned a quantity TLV");
    assert_eq!(result.type_id, PointerType::Quantity);
    let amount_out = QuantityValueV1::decode_frame(result.payload)
        .expect("decode canonical swap quantity")
        .into_quantity();
    // 6) Report the typed result. The host retains the updated mock balances.
    println!("Swap result: sold {amount_in} USDC for {amount_out} ETH (quoted)");
    println!("Accounts: trader={alice} ; pool={pool}");
    println!("Assets: input={asset_a} ; output={asset_b}");
    println!("Done.");
    Ok(())
}
