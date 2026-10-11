//! Every strict instruction envelope family keeps its exact native round trip.
//!
//! Round-trip cases render a native instruction through `instruction_to_json_value`,
//! re-admit the rendered envelope through `value_to_instruction` and require the
//! canonical Norito frame and the rendered JSON to stay unchanged. Routing cases pin
//! the first strict diagnostic of every envelope helper, so a payload can only reach
//! the helper that owns its key.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::smart_contract::ContractArtifactId;
use iroha_data_model::{
    asset::definition::ConfidentialPolicyMode, isi::TransferAssetBatchEntry, proof::VerifyingKeyId,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::NumericSpec;
use norito::json::Value;

const FIXTURE_NETWORK_PREFIX: u16 = 753;
const CONTRACT_ADDRESS: &str = "irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp";

/// Envelope JSON paired with the exact diagnostic of the helper that owns its key.
const ROUTING_CASES: [(&str, &str); 52] = [
    (
        r#"{"SetAssetTransferAvailability":{}}"#,
        "SetAssetTransferAvailability.account_id field missing",
    ),
    (
        r#"{"SetAssetTransferBlacklist":null}"#,
        "SetAssetTransferBlacklist must be an object",
    ),
    (
        r#"{"SetAssetTransferControl":null}"#,
        "SetAssetTransferControl must be an object",
    ),
    (
        r#"{"DeploySoracloudService":{},"Extra":null}"#,
        "DeploySoracloudService instruction envelope contains unexpected field(s): Extra",
    ),
    (
        r#"{"DeploySoracloudAgentApartment":{},"Extra":null}"#,
        "DeploySoracloudAgentApartment instruction envelope contains unexpected field(s): Extra",
    ),
    (
        r#"{"JoinSoracloudHfSharedLease":{},"Extra":null}"#,
        "JoinSoracloudHfSharedLease instruction envelope contains unexpected field(s): Extra",
    ),
    (
        r#"{"Settlement":{"Unknown":{}}}"#,
        "unsupported Settlement instruction variant `Unknown`",
    ),
    (
        r#"{"Settlement":{"Atomic":{}}}"#,
        "Atomic is missing field(s): network_id, settlement_id, movements, expires_at_height, metadata",
    ),
    (
        r#"{"Settlement":{"SettleFxCorridor":{}}}"#,
        "SettleFxCorridor is missing field(s): policy_id, expected_policy_revision, source_asset_definition_id, destination_asset_definition_id, settlement_id, recipient, source_amount, expected_destination_amount, oracle_evidence",
    ),
    (
        r#"{"TransferAssetBatch":{}}"#,
        "TransferAssetBatch.mode field missing",
    ),
    (
        r#"{"CancelSmartContractCodeUpload":null}"#,
        "CancelSmartContractCodeUpload must be an object",
    ),
    (
        r#"{"Register":{}}"#,
        "Register instruction must contain exactly one variant",
    ),
    (
        r#"{"Register":{"Trigger":null}}"#,
        "Register.Trigger must be an object with exact id and action fields",
    ),
    (
        r#"{"Mint":{"TriggerRepetitions":{}}}"#,
        "Mint.TriggerRepetitions.object field missing",
    ),
    (
        r#"{"Unregister":{}}"#,
        "unsupported Unregister instruction variant; expected keys: Peer, Domain, Account, AssetDefinition, Nft, Role, Trigger",
    ),
    (
        r#"{"Burn":{"Asset":{}}}"#,
        "Burn.Asset.object field missing",
    ),
    (
        r#"{"Burn":{}}"#,
        "unsupported Burn instruction variant; expected keys: Asset or TriggerRepetitions",
    ),
    (
        r#"{"ExecuteTrigger":{}}"#,
        "ExecuteTrigger.trigger field missing",
    ),
    (
        r#"{"Transfer":{"Asset":{}}}"#,
        "Transfer.Asset.source field missing",
    ),
    (
        r#"{"Transfer":{"Domain":{}}}"#,
        "Transfer.Domain.source field missing",
    ),
    (
        r#"{"Transfer":{"AssetDefinition":{}}}"#,
        "Transfer.AssetDefinition.source field missing",
    ),
    (
        r#"{"Transfer":{"Nft":{}}}"#,
        "Transfer.Nft.source field missing",
    ),
    (
        r#"{"Transfer":{}}"#,
        "unsupported Transfer instruction variant; expected keys: Asset, Domain, AssetDefinition, or Nft",
    ),
    (
        r#"{"Grant":{}}"#,
        "unsupported Grant instruction variant; expected key: Permission",
    ),
    (
        r#"{"SetAssetDefinitionAlias":{}}"#,
        "SetAssetDefinitionAlias.asset_definition_id field missing",
    ),
    (r#"{"RegisterRwa":{}}"#, "RegisterRwa.rwa field missing"),
    (r#"{"TransferRwa":{}}"#, "TransferRwa.source field missing"),
    (
        r#"{"ForceTransferRwa":{}}"#,
        "ForceTransferRwa.rwa field missing",
    ),
    (
        r#"{"SetRwaControls":{}}"#,
        "SetRwaControls.rwa field missing",
    ),
    (
        r#"{"SetRwaKeyValue":{}}"#,
        "SetRwaKeyValue.rwa field missing",
    ),
    (
        r#"{"SetKeyValue":{}}"#,
        "SetKeyValue currently supports the Account and Nft variants",
    ),
    (
        r#"{"RemoveRwaKeyValue":{}}"#,
        "RemoveRwaKeyValue.rwa field missing",
    ),
    (
        r#"{"Kaigi":{}}"#,
        "unsupported Kaigi instruction variant; see iroha_data_model::isi::kaigi for supported set",
    ),
    (
        r#"{"Kaigi":{"CreateKaigi":{}}}"#,
        "CreateKaigi.call field missing",
    ),
    (
        r#"{"Kaigi":{"JoinKaigi":{}}}"#,
        "JoinKaigi.call_id field missing",
    ),
    (
        r#"{"Kaigi":{"LeaveKaigi":{}}}"#,
        "LeaveKaigi.call_id field missing",
    ),
    (
        r#"{"Kaigi":{"EndKaigi":{}}}"#,
        "EndKaigi.call_id field missing",
    ),
    (
        r#"{"Kaigi":{"RecordKaigiUsage":{}}}"#,
        "RecordKaigiUsage.call_id field missing",
    ),
    (
        r#"{"Kaigi":{"SetKaigiRelayManifest":{}}}"#,
        "SetKaigiRelayManifest.call_id field missing",
    ),
    (
        r#"{"Kaigi":{"RegisterKaigiRelay":{}}}"#,
        "RegisterKaigiRelay.relay field missing",
    ),
    (
        r#"{"Kaigi":{"UnregisterKaigiRelay":{}}}"#,
        "UnregisterKaigiRelay.relay_id field missing",
    ),
    (
        r#"{"Kaigi":{"ReportKaigiRelayHealth":{}}}"#,
        "ReportKaigiRelayHealth.call_id field missing",
    ),
    (
        r#"{"ProposeDeployContract":{}}"#,
        "ProposeDeployContract.contract_address field missing",
    ),
    (
        r#"{"RegisterCitizen":{}}"#,
        "RegisterCitizen.owner field missing",
    ),
    (
        r#"{"SubmitAgendaProposal":{}}"#,
        "SubmitAgendaProposal.proposal field missing",
    ),
    (
        r#"{"RegisterSmartContractBytes":{}}"#,
        "RegisterSmartContractBytes must contain exactly [artifact_id, code]; missing [artifact_id, code], unexpected []",
    ),
    (
        r#"{"RemoveSmartContractBytes":{}}"#,
        "RemoveSmartContractBytes must contain exactly [artifact_id]; missing [artifact_id], unexpected []",
    ),
    (r#"{"zk":{}}"#, "unsupported zk instruction variant"),
    (
        r#"{"ClaimTwitterFollowReward":{}}"#,
        "ClaimTwitterFollowReward.binding_hash field missing",
    ),
    (
        r#"{"SendToTwitter":{}}"#,
        "SendToTwitter.binding_hash field missing",
    ),
    (
        r#"{"CancelTwitterEscrow":{}}"#,
        "CancelTwitterEscrow.binding_hash field missing",
    ),
    (r#"{"Custom":{}}"#, "Custom.payload field missing"),
];

fn account(seed: u8) -> AccountId {
    let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("fixture key");
    AccountId::new(key.public_key().clone())
}

fn name(literal: &str) -> Name {
    literal.parse().expect("fixture name")
}

fn domain() -> DomainId {
    DomainId::try_new("codec", "universal").expect("fixture domain")
}

fn definition() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(domain(), name("coin"))
}

fn nft() -> NftId {
    NftId::of(domain(), name("badge"))
}

fn trigger() -> TriggerId {
    TriggerId::new(name("settle_daily"))
}

fn role(literal: &str) -> RoleId {
    json::from_value(Value::String(literal.to_owned())).expect("fixture role")
}

fn rwa() -> RwaId {
    RwaId::new(domain(), Hash::new(b"envelope-family-rwa"))
}

fn call() -> KaigiId {
    KaigiId::new(domain(), name("standup"))
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// Render, re-admit and re-render `instruction`, returning its strict JSON envelope.
fn assert_roundtrip(instruction: &InstructionBox) -> Value {
    let value = instruction_to_json_value(instruction).expect("strict JSON rendering");
    let restored = value_to_instruction(value.clone()).expect("strict JSON admission");
    assert_eq!(
        norito::encode_canonical(&restored).expect("restored frame"),
        norito::encode_canonical(instruction).expect("native frame"),
        "{value:?}"
    );
    assert_eq!(
        instruction_to_json_value(&restored).expect("re-rendered JSON"),
        value
    );
    value
}

/// Require that `value` renders `variant` inside the `family` envelope.
fn assert_variant(value: &Value, family: &str, variant: &str) {
    let variants = value[family].as_object().expect("family envelope");
    assert!(variants.contains_key(variant), "{value:?}");
    assert_eq!(value.as_object().expect("envelope").len(), 1, "{value:?}");
}

#[test]
fn envelope_helpers_report_their_own_first_strict_diagnostic() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    for (source, reason) in ROUTING_CASES {
        let value: Value = json::from_json(source).expect("routing fixture JSON");
        let error = value_to_instruction(value).expect_err(source);
        assert_eq!(error.kind(), CodecErrorKind::InvalidArgument, "{source}");
        assert_eq!(error.reason(), reason, "{source}");
    }
}

#[test]
fn asset_transfer_control_envelopes_roundtrip_native_frames() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let holder = account(0x11);
    let limits = vec![
        AssetTransferLimit {
            window: AssetTransferControlWindow::Day,
            cap_amount: Some(Quantity::from(5_u32)),
        },
        AssetTransferLimit {
            window: AssetTransferControlWindow::Month,
            cap_amount: None,
        },
    ];
    let cases: [(&str, InstructionBox); 4] = [
        (
            "SetAssetTransferAvailability",
            SetAssetTransferAvailability::new(
                holder.clone(),
                definition(),
                7,
                AssetTransferAvailability::Enabled,
                AssetTransferAvailability::Disabled,
                Some("compliance review".to_owned()),
            )
            .into(),
        ),
        (
            "SetAssetTransferAvailability",
            SetAssetTransferAvailability::new(
                holder.clone(),
                definition(),
                u64::MAX,
                AssetTransferAvailability::Disabled,
                AssetTransferAvailability::Enabled,
                None,
            )
            .into(),
        ),
        (
            "SetAssetTransferBlacklist",
            SetAssetTransferBlacklist::new(holder.clone(), definition(), true).into(),
        ),
        (
            "SetAssetTransferControl",
            SetAssetTransferControl::new(holder, definition(), limits).into(),
        ),
    ];
    for (label, instruction) in cases {
        let value = assert_roundtrip(&instruction);
        assert!(value[label].is_object(), "{value:?}");
    }
}

#[test]
fn ledger_quantity_ownership_and_metadata_envelopes_roundtrip_native_frames() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let (owner, receiver) = (account(0x21), account(0x22));
    let asset = AssetId::new(definition(), owner.clone());
    let cases: [(&str, &str, InstructionBox); 10] = [
        (
            "Mint",
            "Asset",
            MintBox::Asset(Mint::asset_quantity(Quantity::from(10_u32), asset.clone())).into(),
        ),
        (
            "Mint",
            "TriggerRepetitions",
            MintBox::TriggerRepetitions(Mint::trigger_repetitions(3, trigger())).into(),
        ),
        (
            "Burn",
            "Asset",
            BurnBox::Asset(Burn::asset_quantity(Quantity::from(2_u32), asset.clone())).into(),
        ),
        (
            "Burn",
            "TriggerRepetitions",
            BurnBox::TriggerRepetitions(Burn::trigger_repetitions(1, trigger())).into(),
        ),
        (
            "Transfer",
            "Asset",
            TransferBox::Asset(Transfer::asset_quantity(
                asset,
                Quantity::from(4_u32),
                receiver.clone(),
            ))
            .into(),
        ),
        (
            "Transfer",
            "Domain",
            TransferBox::Domain(Transfer::domain(owner.clone(), domain(), receiver.clone())).into(),
        ),
        (
            "Transfer",
            "AssetDefinition",
            TransferBox::AssetDefinition(Transfer::asset_definition(
                owner.clone(),
                definition(),
                receiver.clone(),
            ))
            .into(),
        ),
        (
            "Transfer",
            "Nft",
            TransferBox::Nft(Transfer::nft(owner.clone(), nft(), receiver)).into(),
        ),
        (
            "SetKeyValue",
            "Account",
            SetKeyValue::account(owner, name("tier"), Json::from(2_u32)).into(),
        ),
        (
            "SetKeyValue",
            "Nft",
            SetKeyValue::nft(nft(), name("color"), Json::from("teal")).into(),
        ),
    ];
    for (family, variant, instruction) in cases {
        assert_variant(&assert_roundtrip(&instruction), family, variant);
    }
    let execute = InstructionBox::from(ExecuteTrigger {
        trigger: trigger(),
        args: Json::from(object([("epoch", Value::from(9_u64))])),
    });
    let value = assert_roundtrip(&execute);
    assert_eq!(value["ExecuteTrigger"]["args"]["epoch"].as_u64(), Some(9));
}

#[test]
fn registration_and_removal_envelopes_roundtrip_native_frames() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let cases: [(&str, &str, InstructionBox); 8] = [
        (
            "Register",
            "Domain",
            RegisterBox::Domain(Register::<Domain>::domain(Domain::new(domain()))).into(),
        ),
        (
            "Register",
            "Nft",
            RegisterBox::Nft(Register::<Nft>::nft(Nft::new(nft(), Metadata::default()))).into(),
        ),
        (
            "Register",
            "Role",
            RegisterBox::Role(Register::<Role>::role(Role::new(
                role("auditor"),
                account(0x31),
            )))
            .into(),
        ),
        (
            "Unregister",
            "Domain",
            UnregisterBox::Domain(Unregister::<Domain>::domain(domain())).into(),
        ),
        (
            "Unregister",
            "AssetDefinition",
            UnregisterBox::AssetDefinition(Unregister::<AssetDefinition>::asset_definition(
                definition(),
            ))
            .into(),
        ),
        (
            "Unregister",
            "Nft",
            UnregisterBox::Nft(Unregister::<Nft>::nft(nft())).into(),
        ),
        (
            "Unregister",
            "Role",
            UnregisterBox::Role(Unregister::<Role>::role(role("auditor"))).into(),
        ),
        (
            "Unregister",
            "Trigger",
            UnregisterBox::Trigger(Unregister::<Trigger>::trigger(trigger())).into(),
        ),
    ];
    for (family, variant, instruction) in cases {
        assert_variant(&assert_roundtrip(&instruction), family, variant);
    }
}

#[test]
fn rwa_registry_envelopes_roundtrip_boxed_and_concrete_forms() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let controller = account(0x41);
    let controls = RwaControlPolicy {
        controller_accounts: vec![controller.clone()],
        controller_roles: vec![role("custodian")],
        freeze_enabled: true,
        hold_enabled: false,
        force_transfer_enabled: true,
        redeem_enabled: true,
    };
    let register = RegisterRwa {
        rwa: NewRwa::new(
            domain(),
            Quantity::from(100_u32),
            NumericSpec::integer(),
            "warehouse-receipt-42".to_owned(),
            Some(name("active")),
            Metadata::default(),
            vec![RwaParentRef::new(rwa(), Quantity::from(1_u32))],
            controls.clone(),
        ),
    };
    let transfer = TransferRwa {
        source: controller,
        rwa: rwa(),
        quantity: Quantity::from(5_u32),
        destination: account(0x42),
    };
    let force_transfer = ForceTransferRwa {
        rwa: rwa(),
        quantity: Quantity::from(2_u32),
        destination: account(0x43),
    };
    let set_controls = SetRwaControls {
        rwa: rwa(),
        controls,
    };
    let cases: [(&str, RwaInstructionBox, InstructionBox); 4] = [
        (
            "RegisterRwa",
            register.clone().into(),
            Box::new(register).into_instruction_box(),
        ),
        (
            "TransferRwa",
            transfer.clone().into(),
            Box::new(transfer).into_instruction_box(),
        ),
        (
            "ForceTransferRwa",
            force_transfer.clone().into(),
            Box::new(force_transfer).into_instruction_box(),
        ),
        (
            "SetRwaControls",
            set_controls.clone().into(),
            Box::new(set_controls).into_instruction_box(),
        ),
    ];
    for (label, boxed, concrete) in cases {
        let value = assert_roundtrip(&InstructionBox::from(boxed));
        assert!(value[label].is_object(), "{value:?}");
        assert_eq!(instruction_to_json_value(&concrete).unwrap(), value);
    }
    let metadata_cases: [(&str, RwaInstructionBox); 2] = [
        (
            "SetRwaKeyValue",
            SetKeyValue::rwa(rwa(), name("grade"), Json::from("A")).into(),
        ),
        (
            "RemoveRwaKeyValue",
            RemoveKeyValue::rwa(rwa(), name("grade")).into(),
        ),
    ];
    for (label, boxed) in metadata_cases {
        let value = assert_roundtrip(&InstructionBox::from(boxed));
        assert_eq!(value[label]["key"], Value::String("grade".to_owned()));
    }
}

#[test]
fn kaigi_participant_and_relay_envelopes_roundtrip_native_frames() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let (guest, relay) = (account(0x52), account(0x53));
    let cases: [(&str, InstructionBox); 4] = [
        (
            "JoinKaigi",
            Box::new(JoinKaigi {
                call_id: call(),
                participant: guest.clone(),
                commitment: None,
                nullifier: None,
                roster_root: Some(Hash::new(b"kaigi-roster")),
                proof: Some(vec![1, 2, 3]),
            })
            .into_instruction_box(),
        ),
        (
            "LeaveKaigi",
            Box::new(LeaveKaigi {
                call_id: call(),
                participant: guest,
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: None,
            })
            .into_instruction_box(),
        ),
        (
            "RegisterKaigiRelay",
            Box::new(RegisterKaigiRelay {
                relay: KaigiRelayRegistration {
                    relay_id: relay.clone(),
                    hpke_public_key: vec![9; 32],
                    bandwidth_class: 2,
                },
            })
            .into_instruction_box(),
        ),
        (
            "UnregisterKaigiRelay",
            Box::new(UnregisterKaigiRelay { relay_id: relay }).into_instruction_box(),
        ),
    ];
    for (variant, instruction) in cases {
        assert_variant(&assert_roundtrip(&instruction), "Kaigi", variant);
    }
}

#[test]
fn governance_and_code_byte_envelopes_roundtrip_native_frames() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let artifact_id = ContractArtifactId::new(
        DataSpaceId::new(u64::MAX),
        Hash::new(b"envelope-family-code"),
    );
    let cases: [(&str, InstructionBox); 5] = [
        (
            "ProposeDeployContract",
            Box::new(ProposeDeployContract {
                contract_address: CONTRACT_ADDRESS.parse().expect("contract address"),
                code_hash: ContractCodeHash::new([0xaa; 32]),
                abi_hash: ContractAbiHash::new([0xbb; 32]),
                abi_version: AbiVersion::new(1),
                manifest_provenance: None,
            })
            .into_instruction_box(),
        ),
        (
            "RegisterCitizen",
            Box::new(RegisterCitizen {
                owner: account(0x61),
                amount: Quantity::from(10_000_u32),
            })
            .into_instruction_box(),
        ),
        (
            "RegisterSmartContractBytes",
            Box::new(RegisterSmartContractBytes {
                artifact_id,
                code: vec![0x49, 0x56, 0x4d, 0x00],
            })
            .into_instruction_box(),
        ),
        (
            "RemoveSmartContractBytes",
            Box::new(RemoveSmartContractBytes {
                artifact_id,
                reason: Some("superseded".to_owned()),
            })
            .into_instruction_box(),
        ),
        (
            "RemoveSmartContractBytes",
            Box::new(RemoveSmartContractBytes {
                artifact_id,
                reason: None,
            })
            .into_instruction_box(),
        ),
    ];
    for (label, instruction) in cases {
        let value = assert_roundtrip(&instruction);
        assert!(value[label].is_object(), "{value:?}");
    }
}

#[test]
fn zk_envelopes_roundtrip_native_frames() {
    let transition = Hash::new(b"envelope-family-transition");
    let key = |key_name: &str| VerifyingKeyId::new("halo2/ipa", key_name);
    let cases: [(&str, InstructionBox); 5] = [
        (
            "RegisterZkAsset",
            Box::new(RegisterZkAsset::new(definition(), None)).into_instruction_box(),
        ),
        (
            "RegisterZkAsset",
            Box::new(RegisterZkAsset::new(definition(), Some(key("vk_unshield"))))
                .into_instruction_box(),
        ),
        (
            "ScheduleConfidentialPolicyTransition",
            Box::new(ScheduleConfidentialPolicyTransition::new(
                definition(),
                ConfidentialPolicyMode::Convertible,
                1_024,
                transition,
                Some(64),
            ))
            .into_instruction_box(),
        ),
        (
            "CancelConfidentialPolicyTransition",
            Box::new(CancelConfidentialPolicyTransition::new(
                definition(),
                transition,
            ))
            .into_instruction_box(),
        ),
        (
            "CreateElection",
            Box::new(CreateElection {
                election_id: "budget-2026".to_owned(),
                options: 2,
                eligible_root: [3; 32],
                start_ts: 1,
                end_ts: 2,
                vk_ballot: key("vk_ballot"),
                vk_tally: key("vk_tally"),
                domain_tag: "ballot-v1".to_owned(),
            })
            .into_instruction_box(),
        ),
    ];
    for (variant, instruction) in cases {
        assert_variant(&assert_roundtrip(&instruction), "zk", variant);
    }
}

#[test]
fn social_escrow_envelopes_roundtrip_native_frames() {
    let binding_hash = KeyedHash {
        pepper_id: "pepper-2026".to_owned(),
        digest: Hash::new(b"@iroha"),
    };
    let cases: [(&str, InstructionBox); 3] = [
        (
            "ClaimTwitterFollowReward",
            Box::new(ClaimTwitterFollowReward {
                binding_hash: binding_hash.clone(),
            })
            .into_instruction_box(),
        ),
        (
            "SendToTwitter",
            Box::new(SendToTwitter {
                binding_hash: binding_hash.clone(),
                amount: Quantity::from(25_u32),
            })
            .into_instruction_box(),
        ),
        (
            "CancelTwitterEscrow",
            Box::new(CancelTwitterEscrow { binding_hash }).into_instruction_box(),
        ),
    ];
    for (label, instruction) in cases {
        let value = assert_roundtrip(&instruction);
        assert_eq!(
            value[label]["binding_hash"]["pepper_id"],
            Value::String("pepper-2026".to_owned())
        );
    }
}

#[test]
fn multisig_envelopes_wrap_their_payloads_in_custom_instructions() {
    let fields = object([("account", Value::String("multisig-fixture".to_owned()))]);
    for (key, wrapper) in [
        ("MultisigPropose", "Propose"),
        ("MultisigApprove", "Approve"),
        ("MultisigCancel", "Cancel"),
        ("MultisigRegister", "Register"),
    ] {
        let fields = if key == "MultisigRegister" {
            object([
                ("account", Value::String("multisig-fixture".to_owned())),
                ("uaid", Value::Null),
            ])
        } else {
            fields.clone()
        };
        let expected = custom_json_value(object([(wrapper, fields.clone())]));
        for spelling in [
            key.to_owned(),
            key.to_ascii_lowercase(),
            key.to_ascii_uppercase(),
        ] {
            let instruction = value_to_instruction(object([(spelling.as_str(), fields.clone())]))
                .expect("multisig envelope");
            assert_eq!(instruction_to_json_value(&instruction).unwrap(), expected);
        }
        let error = value_to_instruction(object([(key, Value::Null)])).unwrap_err();
        assert!(
            error
                .reason()
                .starts_with(&format!("{key} payload must be an object")),
            "{error}"
        );
    }
    let instruction =
        value_to_instruction(object([("Multisig", fields.clone())])).expect("multisig payload");
    assert_eq!(
        instruction_to_json_value(&instruction).unwrap(),
        custom_json_value(fields)
    );
    let error = value_to_instruction(object([("multisig", Value::Bool(true))])).unwrap_err();
    assert!(
        error
            .reason()
            .starts_with("Multisig instruction payload must be an object"),
        "{error}"
    );
}

/// Batch entries with a derived and an explicit leg identifier.
fn batch_entries() -> Vec<TransferAssetBatchEntry> {
    vec![
        TransferAssetBatchEntry::new(
            account(0x71),
            account(0x72),
            definition(),
            Quantity::from(3_u32),
        ),
        TransferAssetBatchEntry::with_leg_id(
            "payroll-2026-09/leg-2",
            account(0x73),
            account(0x74),
            definition(),
            Quantity::from(4_u32),
        ),
    ]
}

/// First rendered entry of a batch payload.
fn first_entry(batch: &mut json::Map) -> &mut json::Map {
    batch
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .and_then(|entries| entries.first_mut())
        .and_then(Value::as_object_mut)
        .expect("first batch entry")
}

/// Admission error for the rendered batch `value` after `edit` changes its payload.
fn batch_rejection(value: &Value, edit: impl FnOnce(&mut json::Map)) -> String {
    let mut edited = value.clone();
    let batch = edited
        .as_object_mut()
        .and_then(|envelope| envelope.get_mut("TransferAssetBatch"))
        .and_then(Value::as_object_mut)
        .expect("batch payload");
    edit(batch);
    let error = value_to_instruction(edited).expect_err("edited batch must be rejected");
    assert_eq!(error.kind(), CodecErrorKind::InvalidArgument, "{error}");
    error.reason().to_owned()
}

#[test]
fn transfer_asset_batch_envelope_keeps_mode_and_leg_identifiers() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    for batch in [
        TransferAssetBatch::new(batch_entries()),
        TransferAssetBatch::independent(batch_entries()),
    ] {
        let value = assert_roundtrip(&InstructionBox::from(batch));
        assert_eq!(
            value["TransferAssetBatch"]["entries"][1]["leg_id"],
            Value::String("payroll-2026-09/leg-2".to_owned())
        );
    }
    let value = instruction_to_json_value(&InstructionBox::from(TransferAssetBatch::new(
        batch_entries(),
    )))
    .expect("batch JSON");
    assert_eq!(
        batch_rejection(&value, |batch| {
            batch.remove("mode");
        }),
        "TransferAssetBatch.mode field missing"
    );
    assert_eq!(
        batch_rejection(&value, |batch| {
            batch.insert("redirect".to_owned(), Value::Bool(true));
        }),
        "TransferAssetBatch contains unexpected field(s): redirect"
    );
    assert_eq!(
        batch_rejection(&value, |batch| {
            first_entry(batch).remove("leg_id");
        }),
        "TransferAssetBatch.entries[0].leg_id field missing"
    );
    assert_eq!(
        batch_rejection(&value, |batch| {
            first_entry(batch).insert("memo".to_owned(), Value::Null);
        }),
        "TransferAssetBatch.entries[0] contains unexpected field(s): memo"
    );
}
