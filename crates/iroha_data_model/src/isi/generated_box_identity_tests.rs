//! Exhaustive captured frames for the generated instruction-box variants.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

use norito::{
    NoritoDeserialize, NoritoSchema, NoritoSerialize,
    json::{self, Value},
};

use super::{
    GrantBox, InstructionBox, RemoveKeyValueBox, RevokeBox, SetKeyValueBox,
    defi::DeFiInstructionBox,
    mint_burn::{BurnBox, MintBox},
    register::{RegisterBox, UnregisterBox},
    rwa::RwaInstructionBox,
    settlement::SettlementInstructionBox,
    transfer::TransferBox,
};

use crate::fixture_json;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("String formatting");
    }
    out
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "complete fixture hex bytes");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).expect("fixture hex UTF8"), 16)
                .expect("fixture hex byte")
        })
        .collect()
}

fn frame<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + PartialEq + Debug,
{
    let bytes = norito::to_bytes(value).expect("encode instruction box frame");
    let decoded: T = norito::decode_from_bytes(&bytes).expect("decode instruction box frame");
    assert_eq!(&decoded, value);
    hex(&bytes)
}

pub(super) fn case<T>(variant: &str, value: T) -> Value
where
    T: NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + Clone
        + Into<InstructionBox>
        + Debug
        + PartialEq,
{
    let instruction: InstructionBox = value.clone().into();
    let carrier_json = json::to_value(&instruction).expect("instruction carrier JSON");
    let decoded: InstructionBox =
        json::from_value(carrier_json.clone()).expect("decode instruction carrier JSON");
    assert_eq!(decoded, instruction);
    json::object([
        ("variant", Value::String(variant.into())),
        ("frame", Value::String(frame(&value))),
        ("vector_frame", Value::String(frame(&vec![value.clone()]))),
        ("option_frame", Value::String(frame(&Some(value.clone())))),
        (
            "map_frame",
            Value::String(frame(&BTreeMap::from([(7_u8, value)]))),
        ),
        ("instruction_frame", Value::String(frame(&instruction))),
        ("instruction_json", carrier_json),
    ])
    .expect("instruction box case")
}

fn check<T>(variants: &[&str], variant_name: fn(&T) -> &'static str)
where
    T: NoritoSchema
        + NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + Clone
        + Into<InstructionBox>
        + Debug
        + PartialEq,
{
    let capture: Value = json::from_str(include_str!(
        "../../tests/fixtures/instruction_box_generated_identity_frames.json"
    ))
    .expect("immutable instruction box capture");
    let rows = capture.as_array().expect("type rows");
    assert_eq!(rows.len(), 12, "complete captured box-type inventory");
    let nominal = T::nominal_name();
    let matches: Vec<_> = rows
        .iter()
        .filter(|row| row.get("nominal").and_then(Value::as_str) == Some(nominal.as_str()))
        .collect();
    assert_eq!(matches.len(), 1, "exactly one captured type");
    let captured = matches[0];
    let hash = norito::schema::identity::frame_hash::<T>();
    assert_eq!(hash, norito::schema::identity::frame_hash::<T>());
    assert_eq!(hash, norito::schema::identity::frame_hash::<T>());
    assert_eq!(T::nominal_name(), T::frame_name());
    let mut seen = BTreeSet::new();
    let cases = captured
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured cases")
        .iter()
        .map(|row| {
            let bytes = unhex(
                row.get("frame")
                    .and_then(Value::as_str)
                    .expect("captured root frame"),
            );
            let value: T =
                norito::decode_from_bytes(&bytes).expect("decode captured instruction box");
            let variant = variant_name(&value);
            assert!(
                seen.insert(variant),
                "duplicate captured variant: {variant}"
            );
            case(variant, value)
        })
        .collect();
    assert_eq!(
        seen,
        variants.iter().copied().collect(),
        "complete variant inventory"
    );
    let actual = json::object([
        ("nominal", Value::String(T::nominal_name())),
        (
            "serialize_hash",
            Value::String(hex(&norito::schema::identity::frame_hash::<T>())),
        ),
        (
            "deserialize_hash",
            Value::String(hex(&norito::schema::identity::frame_hash::<T>())),
        ),
        ("cases", Value::Array(cases)),
    ])
    .expect("instruction box record");
    fixture_json::assert_json_matches(captured, &actual, &T::nominal_name());
}

macro_rules! check_box {
    ($test:ident, $name:ident, [$($variant:ident),+ $(,)?]) => {
        #[test]
        fn $test() {
            check::<$name>(&[$(stringify!($variant)),+], |value| match value {
                $($name::$variant(_) => stringify!($variant)),+
            });
        }
    };
}
check_box!(
    de_fi_instruction_box_preserves_captured_variants,
    DeFiInstructionBox,
    [
        SubmitIntent,
        SettleIntent,
        RegisterVault,
        VaultRequest,
        RegisterOperator,
        OperatorHeartbeat,
        ConfigureAmmHook,
        HookExecution,
        RegisterMarginMarket,
        UpdateMarginAccount,
        RegisterRwaMarket,
        ReportRwaNav
    ]
);
check_box!(
    mint_box_preserves_captured_variants,
    MintBox,
    [Asset, TriggerRepetitions]
);
check_box!(
    burn_box_preserves_captured_variants,
    BurnBox,
    [Asset, TriggerRepetitions]
);
check_box!(
    set_key_value_box_preserves_captured_variants,
    SetKeyValueBox,
    [Domain, Account, AssetDefinition, Nft, Trigger]
);
check_box!(
    remove_key_value_box_preserves_captured_variants,
    RemoveKeyValueBox,
    [Domain, Account, AssetDefinition, Nft, Trigger]
);
check_box!(
    grant_box_preserves_captured_variants,
    GrantBox,
    [Permission, Role, RolePermission]
);
check_box!(
    revoke_box_preserves_captured_variants,
    RevokeBox,
    [Permission, Role, RolePermission]
);
check_box!(
    register_box_preserves_captured_variants,
    RegisterBox,
    [Peer, Domain, Account, AssetDefinition, Nft, Role, Trigger]
);
check_box!(
    unregister_box_preserves_captured_variants,
    UnregisterBox,
    [Peer, Domain, Account, AssetDefinition, Nft, Role, Trigger]
);
check_box!(
    rwa_instruction_box_preserves_captured_variants,
    RwaInstructionBox,
    [
        Register,
        Transfer,
        Merge,
        Redeem,
        Freeze,
        Unfreeze,
        Hold,
        Release,
        ForceTransfer,
        SetControls,
        SetKeyValue,
        RemoveKeyValue
    ]
);
check_box!(
    settlement_instruction_box_preserves_captured_variants,
    SettlementInstructionBox,
    [
        Dvp,
        Pvp,
        SetFxCorridorPolicy,
        FundFxCorridorEscrow,
        RefundFxCorridorEscrow,
        SettleFxCorridor,
        Atomic
    ]
);
check_box!(
    transfer_box_preserves_captured_variants,
    TransferBox,
    [Domain, AssetDefinition, Asset, Nft]
);
