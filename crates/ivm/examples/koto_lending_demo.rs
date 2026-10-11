//! Kotodama lending demo: a minimal borrow/mint flow on IVM.
use iroha_crypto::Hash;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric::Quantity};
use ivm::{
    AccountId, AssetDefinitionId, IVM, MockWorldStateView, PermissionToken, PointerType,
    ProgramMetadata, mock_wsv::WsvHost,
};
use ivm_abi::arguments::encode_argument_record_from_json;
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use std::collections::BTreeMap;
fn fixture_account(_domain: &str, hex_public_key: &str) -> AccountId {
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
    let src = include_str!("../../kotodama_lang/src/samples/lending_simple.ko");
    let compiler = KotodamaCompiler::new();
    let bytecode = compiler
        .compile_source(src)
        .expect("compile lending_simple");
    let metadata = ProgramMetadata::parse(&bytecode).expect("parse lending_simple metadata");
    let borrow = metadata
        .contract_interface
        .as_ref()
        .expect("lending_simple contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "borrow")
        .expect("borrow entrypoint descriptor");
    let entrypoint_pc =
        u64::try_from(metadata.prefix_len()).expect("program prefix fits u64") + borrow.entry_pc;
    // 2) Prepare a tiny world with a user, a vault account, and a debt asset
    let user = fixture_account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    let vault = fixture_account(
        "genesis",
        "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4",
    );
    let debt_asset: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "stable".parse()?,
        );
    // Seed the canonical accounts and asset definition with zero balances, then
    // grant permission for the user to mint through the host.
    let mut wsv = MockWorldStateView::with_balances(&[
        ((user.clone(), debt_asset.clone()), Quantity::zero()),
        ((vault.clone(), debt_asset.clone()), Quantity::zero()),
    ]);
    wsv.grant_permission(&user, PermissionToken::MintAsset(debt_asset.clone()));
    wsv.grant_permission(&user, PermissionToken::ReadAccountAssets(user.clone()));
    let user_subject = user.clone();
    // 3) Encode the Torii boundary payload as the schema-bound V1 argument record.
    let arguments = Json::from(norito::json!({
        "user": (user.to_string()),
        "_vault_account": (vault.to_string()),
        "debt_asset": (debt_asset.canonical_address()),
        "amount": "500",
        "collateral_value": "10000",
        "current_debt_value": "0",
        "min_ratio_bps": "1500",
    }));
    let schema = borrow
        .argument_schema
        .as_ref()
        .expect("borrow entrypoint argument schema");
    let record = encode_argument_record_from_json(schema, &arguments)
        .expect("encode canonical borrow argument record");
    let input_name: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key is a Name");
    let host = WsvHost::new_with_subject(wsv, user_subject).with_public_inputs(BTreeMap::from([(
        input_name,
        tlv(PointerType::NoritoBytes, &record),
    )]));
    // 4) Create the VM, attach the host, and select the public wrapper.
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&bytecode).expect("load program");
    vm.set_program_counter(entrypoint_pc)
        .expect("select borrow entrypoint");
    vm.run().expect("run VM");
    println!("Borrow executed. User should have 500 of {debt_asset}.");
    println!("Done.");
    Ok(())
}
