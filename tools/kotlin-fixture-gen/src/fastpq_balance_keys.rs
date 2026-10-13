//! Canonical typed FASTPQ keys over the independently checked complete-controller fixture.

use iroha_data_model::{
    account::AccountId, asset::id::AssetDefinitionId, fastpq::transfer_balance_key,
};
use norito::{json, json::Value};

pub fn emit() {
    let source: Value = norito::json::from_str(include_str!(
        "../../../fixtures/account/multisig_wire_v1.json"
    ))
    .expect("canonical account fixture");
    let uuid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01,
    ];
    let asset = AssetDefinitionId::from_uuid_bytes(uuid).unwrap();
    let positive = source
        .get("positive")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let name = case.get("name").unwrap().as_str().unwrap();
            let account_hex = case.get("account_id_frame_hex").unwrap().as_str().unwrap();
            let account: AccountId =
                norito::decode_canonical(&hex::decode(account_hex).unwrap()).unwrap();
            let key = transfer_balance_key(&asset, &account).unwrap();
            let decoded: iroha_data_model::fastpq::FastpqBalanceKeyV1 =
                norito::decode_canonical(&key).unwrap();
            assert_eq!(decoded.asset_definition, asset);
            assert_eq!(decoded.account, account);
            json!({
                "name": name,
                "account_id_frame_hex": account_hex,
                "key_frame_hex": (hex::encode(key)),
            })
        })
        .collect::<Vec<_>>();
    let fixture = json!({
        "schema": "iroha.fastpq.balance-key.v1",
        "asset_uuid_hex": (hex::encode(uuid)),
        "layout_flags": 2u64,
        "positive": positive,
    });
    println!("{}", norito::json::to_json(&fixture).unwrap());
}
