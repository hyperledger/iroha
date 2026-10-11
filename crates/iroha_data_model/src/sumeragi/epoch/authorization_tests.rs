//! Canonical codec, schema and succession coverage for scheduling epoch authorizations.

use super::*;
use crate::block::BlockHeader;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_model_base::peer::PeerId;
use norito::codec::DecodeAll as _;
use std::any::TypeId;

fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"validator-epoch-authorization",
    )))
}

fn signing_generation(generation: u64) -> ValidatorGenerationV1 {
    signing_generation_with_seeds(generation, 1)
}

fn signing_generation_with_seeds(generation: u64, first_seed: u8) -> ValidatorGenerationV1 {
    let mut validators = (first_seed..first_seed + 4)
        .map(|seed| {
            PeerId::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                    .unwrap()
                    .public_key()
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    validators.sort();
    let generation = ValidatorGenerationV1 {
        network_id: network(),
        generation,
        validators,
    };
    generation.validate().unwrap();
    generation
}

fn genesis_authorization() -> ValidatorEpochAuthorizationV1 {
    ValidatorEpochAuthorizationV1::genesis(&signing_generation(0), 10).unwrap()
}

fn retained_authorization(
    previous: &ValidatorEpochAuthorizationV1,
) -> ValidatorEpochAuthorizationV1 {
    ValidatorEpochAuthorizationV1 {
        epoch: previous.epoch + 1,
        first_height: previous.last_height + 1,
        last_height: previous.last_height + 10,
        previous_authorization_id: previous.authorization_id().unwrap(),
        decision: ValidatorEpochDecisionV1::Retain,
        beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
            session_id: [7; 32],
            transcript_hash: [8; 32],
        }),
        ..*previous
    }
}

#[test]
fn beacon_epoch_binding_has_one_tagged_json_and_binary_layout() {
    let installed = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
        session_id: [7; 32],
        transcript_hash: [8; 32],
    });
    let installed_json = format!(
        "{{\"kind\":\"installed\",\"value\":{{\"session_id\":[{}],\"transcript_hash\":[{}]}}}}",
        ["7"; 32].join(","),
        ["8"; 32].join(","),
    );
    // Fixed-v1 COMPACT_LEN: u32 variant, 66-byte body, then two
    // length-prefixed 32-byte fields in their declared order.
    let mut installed_bytes = vec![1, 0, 0, 0, 66, 32];
    installed_bytes.extend([7; 32]);
    installed_bytes.push(32);
    installed_bytes.extend([8; 32]);
    for (value, expected_json, expected_bytes) in [
        (
            BeaconEpochBindingV1::Bootstrap,
            r#"{"kind":"bootstrap","value":null}"#.to_owned(),
            vec![0, 0, 0, 0],
        ),
        (installed, installed_json, installed_bytes),
    ] {
        assert_eq!(norito::json::to_json(&value).unwrap(), expected_json);
        assert_eq!(
            norito::json::from_str::<BeaconEpochBindingV1>(&expected_json).unwrap(),
            value
        );
        assert_eq!(value.encode(), expected_bytes);
        assert_eq!(
            BeaconEpochBindingV1::decode(&mut expected_bytes.as_slice()).unwrap(),
            value
        );
    }
}

#[test]
fn beacon_epoch_binding_rejects_noncanonical_json_shapes() {
    for json in [
        r#""bootstrap""#,
        r#"{"kind":"Bootstrap","value":null}"#,
        r#"{"kind":"unknown","value":null}"#,
        r#"{"kind":"bootstrap"}"#,
        r#"{"kind":"bootstrap","value":{}}"#,
        r#"{"kind":"bootstrap","value":null,"unknown":0}"#,
        r#"{"kind":"bootstrap","kind":"installed","value":null}"#,
        r#"{"kind":"bootstrap","value":null,"value":null}"#,
        r#"{"kind":"installed","value":null}"#,
    ] {
        assert!(
            norito::json::from_str::<BeaconEpochBindingV1>(json).is_err(),
            "{json}"
        );
    }
    let installed = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
        session_id: [7; 32],
        transcript_hash: [8; 32],
    });
    let canonical = norito::json::to_value(&installed).unwrap();
    for mutation in 0..4 {
        let mut malformed = canonical.clone();
        let body = malformed
            .as_object_mut()
            .unwrap()
            .get_mut("value")
            .unwrap()
            .as_object_mut()
            .unwrap();
        match mutation {
            0 => {
                body.insert("unknown".into(), norito::json::Value::Null);
            }
            1 => {
                body.remove("session_id");
            }
            2 => {
                body.insert("session_id".into(), norito::json::Value::Array(Vec::new()));
            }
            _ => {
                body.insert(
                    "transcript_hash".into(),
                    norito::json::Value::String("08".repeat(32)),
                );
            }
        }
        assert!(
            norito::json::from_value::<BeaconEpochBindingV1>(malformed).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn beacon_epoch_binding_roundtrips_both_variants_and_registers_payload_schema() {
    let installed = InstalledBeaconEpochBindingV1 {
        session_id: [7; 32],
        transcript_hash: [8; 32],
    };
    for (binding, tag) in [
        (BeaconEpochBindingV1::Bootstrap, "bootstrap"),
        (BeaconEpochBindingV1::Installed(installed), "installed"),
    ] {
        let bytes = binding.encode();
        let decoded: BeaconEpochBindingV1 =
            BeaconEpochBindingV1::decode_all(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, binding);
        let json = norito::json::to_json(&binding).unwrap();
        let decoded: BeaconEpochBindingV1 = norito::json::from_json(&json).unwrap();
        assert_eq!(decoded, binding);
        let mut value = norito::json::to_value(&binding).unwrap();
        assert_eq!(value.as_object().unwrap()["kind"].as_str(), Some(tag));
        let decoded: BeaconEpochBindingV1 = norito::json::from_value(value.clone()).unwrap();
        assert_eq!(decoded, binding);
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), norito::json::Value::Null);
        assert!(norito::json::from_value::<BeaconEpochBindingV1>(value.clone()).is_err());
        assert!(
            norito::json::from_json::<BeaconEpochBindingV1>(
                &norito::json::to_json(&value).unwrap()
            )
            .is_err()
        );
    }
    let mut value = norito::json::to_value(&BeaconEpochBindingV1::Installed(installed)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .get_mut("value")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), norito::json::Value::Null);
    assert!(norito::json::from_value::<BeaconEpochBindingV1>(value.clone()).is_err());
    assert!(
        norito::json::from_json::<BeaconEpochBindingV1>(&norito::json::to_json(&value).unwrap())
            .is_err()
    );
    let schema = BeaconEpochBindingV1::schema();
    let Some(iroha_schema::Metadata::Enum(metadata)) = schema.get::<BeaconEpochBindingV1>() else {
        panic!("beacon enum schema");
    };
    assert_eq!(metadata.variants.len(), 2);
    assert_eq!(metadata.variants[0].discriminant, 0);
    assert_eq!(metadata.variants[0].ty, None);
    assert_eq!(metadata.variants[1].discriminant, 1);
    assert_eq!(
        metadata.variants[1].ty,
        Some(TypeId::of::<InstalledBeaconEpochBindingV1>())
    );
    let Some(iroha_schema::Metadata::Struct(payload)) =
        schema.get::<InstalledBeaconEpochBindingV1>()
    else {
        panic!("installed payload schema");
    };
    assert_eq!(
        payload
            .declarations
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["session_id", "transcript_hash"]
    );
}

#[test]
fn beacon_epoch_binding_schema_preserves_owner_and_field_order() {
    use iroha_schema::{EnumVariant, Metadata, TypeId as _};
    let schema = BeaconEpochBindingV1::schema();
    let Some(Metadata::Enum(binding)) = schema.get::<BeaconEpochBindingV1>() else {
        panic!("beacon binding schema must be an enum");
    };
    assert_eq!(BeaconEpochBindingV1::id(), "BeaconEpochBindingV1");
    assert_eq!(BeaconEpochBindingV1::type_name(), "BeaconEpochBindingV1");
    assert_eq!(
        binding.variants,
        vec![
            EnumVariant {
                tag: "bootstrap".into(),
                discriminant: 0,
                ty: None
            },
            EnumVariant {
                tag: "installed".into(),
                discriminant: 1,
                ty: Some(TypeId::of::<InstalledBeaconEpochBindingV1>())
            },
        ]
    );
    let Some(Metadata::Struct(body)) = schema.get::<InstalledBeaconEpochBindingV1>() else {
        panic!("installed beacon body must own its named schema fields");
    };
    assert_eq!(
        body.declarations
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["session_id", "transcript_hash"]
    );
    assert!(
        body.declarations
            .iter()
            .all(|field| field.ty == TypeId::of::<[u8; 32]>())
    );
    let decisions = ValidatorEpochDecisionV1::schema();
    let Some(Metadata::Enum(decision)) = decisions.get::<ValidatorEpochDecisionV1>() else {
        panic!("epoch decision schema must be an enum");
    };
    assert_eq!(ValidatorEpochDecisionV1::id(), "ValidatorEpochDecisionV1");
    assert_eq!(
        decision
            .variants
            .iter()
            .map(|variant| (variant.tag.as_str(), variant.discriminant, variant.ty))
            .collect::<Vec<_>>(),
        [
            ("genesis", 0, None),
            ("activate", 1, None),
            ("retain", 2, None),
            ("retain_and_cancel", 3, None),
        ]
    );
}

#[test]
fn epoch_decisions_roundtrip_all_discriminants_and_reject_untagged_json() {
    for (value, tag, discriminant) in [
        (ValidatorEpochDecisionV1::Genesis, "genesis", 0_u32),
        (ValidatorEpochDecisionV1::Activate, "activate", 1),
        (ValidatorEpochDecisionV1::Retain, "retain", 2),
        (
            ValidatorEpochDecisionV1::RetainAndCancel,
            "retain_and_cancel",
            3,
        ),
    ] {
        let json = format!("{{\"kind\":\"{tag}\",\"value\":null}}");
        assert_eq!(norito::json::to_json(&value).unwrap(), json);
        assert_eq!(
            norito::json::from_str::<ValidatorEpochDecisionV1>(&json).unwrap(),
            value
        );
        assert_eq!(u32::from(value as u8), discriminant);
        assert_eq!(value.encode(), discriminant.to_le_bytes());
        assert_eq!(
            ValidatorEpochDecisionV1::decode(&mut discriminant.to_le_bytes().as_slice()).unwrap(),
            value
        );
        let bytes = value.encode();
        assert_eq!(
            ValidatorEpochDecisionV1::decode_all(&mut bytes.as_slice()).unwrap(),
            value
        );
        let decoded: ValidatorEpochDecisionV1 =
            norito::json::from_value(norito::json::to_value(&value).unwrap()).unwrap();
        assert_eq!(decoded, value);
    }
    for json in [
        r#""retain""#,
        r#"{"value":null}"#,
        r#"{"kind":"Genesis","value":null}"#,
        r#"{"kind":"retain_and_cancel","value":0}"#,
        r#"{"kind":"retain","value":null,"unknown":true}"#,
        r#"{"kind":"retain","value":null,"future":1}"#,
        r#"{"kind":"activate"}"#,
    ] {
        assert!(norito::json::from_str::<ValidatorEpochDecisionV1>(json).is_err());
        let value: norito::json::Value = norito::json::from_json(json).unwrap();
        assert!(norito::json::from_value::<ValidatorEpochDecisionV1>(value).is_err());
    }
    assert!(ValidatorEpochDecisionV1::decode(&mut 4_u32.to_le_bytes().as_slice()).is_err());
}

#[test]
fn epoch_authorization_binding_keeps_fixed_width_identity() {
    let genesis = ValidatorEpochAuthorizationV1 {
        version: 1,
        network_id: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([1; 32]),
        )),
        epoch: 0,
        first_height: 1,
        last_height: 10,
        authority_generation: 0,
        authority_id: [2; 32],
        beacon: BeaconEpochBindingV1::Bootstrap,
        previous_authorization_id: [0; 32],
        transition_id: [0; 32],
        decision: ValidatorEpochDecisionV1::Genesis,
    };
    let installed = ValidatorEpochAuthorizationV1 {
        epoch: 1,
        first_height: 11,
        last_height: 20,
        beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
            session_id: [7; 32],
            transcript_hash: [8; 32],
        }),
        previous_authorization_id: [3; 32],
        decision: ValidatorEpochDecisionV1::Retain,
        ..genesis
    };
    // Golden values independently computed from the documented fixed-width SHA-256 transcript.
    for (authorization, expected) in [
        (
            genesis,
            "fa3bbadad8f42a6aa870f4305059688a6924fe6acf2264038311187c7ea1fcd3",
        ),
        (
            installed,
            "92e5c8c73b631a0ed5aa1b324c7dfa29d51964de48271d4c5181aa898668db9b",
        ),
    ] {
        let digest = authorization.authorization_id().unwrap();
        let actual = hex::encode(digest);
        assert_eq!(actual, expected);
        let bytes = authorization.encode();
        let decoded: ValidatorEpochAuthorizationV1 =
            ValidatorEpochAuthorizationV1::decode_all(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, authorization);
        assert_eq!(decoded.authorization_id().unwrap(), digest);
    }
}

#[test]
fn epoch_authorization_digest_is_independent_of_body_framing() {
    let authorization = ValidatorEpochAuthorizationV1 {
        version: 1,
        network_id: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x11; 32]),
        )),
        epoch: 1,
        first_height: 11,
        last_height: 20,
        authority_generation: 0,
        authority_id: [0x22; 32],
        beacon: BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
            session_id: [7; 32],
            transcript_hash: [8; 32],
        }),
        previous_authorization_id: [0x33; 32],
        transition_id: [0; 32],
        decision: ValidatorEpochDecisionV1::Retain,
    };
    // SHA-256 of the fixed 267-byte domain-separated authorization preimage.
    assert_eq!(
        hex::encode(authorization.authorization_id().unwrap()),
        "4d142785bb835f547fbf31b0fd11fcc78f94328e50445a0f8703c39169b61ccf"
    );
    let json = norito::json::to_json(&authorization).unwrap();
    assert_eq!(
        norito::json::from_str::<ValidatorEpochAuthorizationV1>(&json).unwrap(),
        authorization
    );
    assert_eq!(
        ValidatorEpochAuthorizationV1::decode(&mut authorization.encode().as_slice()).unwrap(),
        authorization
    );
}

#[test]
fn epoch_authorization_uses_sumeragi_schema_identity() {
    use norito::schema::identity::NoritoSchema as _;
    assert_eq!(
        ValidatorEpochAuthorizationV1::nominal_name(),
        "iroha_data_model::sumeragi::epoch::ValidatorEpochAuthorizationV1"
    );
    assert_eq!(
        ValidatorEpochAuthorizationV1::frame_name(),
        ValidatorEpochAuthorizationV1::nominal_name()
    );
}

#[test]
fn genesis_authorization_binds_generation_network_and_interval() {
    let authority = signing_generation(0);
    let authorization =
        ValidatorEpochAuthorizationV1::genesis(&authority, 10).expect("valid initial generation");
    authorization
        .validate_against_generation(&authority)
        .unwrap();
    assert_eq!(authorization.network_id, authority.network_id);
    assert_eq!(
        authorization.authority_id,
        authority.generation_id().unwrap()
    );
    assert_eq!(
        (
            authorization.epoch,
            authorization.first_height,
            authorization.last_height
        ),
        (0, 1, 10)
    );
    assert_eq!(authorization.beacon, BeaconEpochBindingV1::Bootstrap);
    assert_eq!(authorization.previous_authorization_id, [0; 32]);
    assert_eq!(authorization.transition_id, [0; 32]);
    assert_eq!(authorization.decision, ValidatorEpochDecisionV1::Genesis);
    let longer = ValidatorEpochAuthorizationV1::genesis(&authority, 11).unwrap();
    assert_ne!(
        authorization.authorization_id().unwrap(),
        longer.authorization_id().unwrap()
    );
    assert_ne!(
        authorization.authorization_id().unwrap(),
        authority.generation_id().unwrap()
    );
}

#[test]
fn genesis_authorization_rejects_invalid_generation_or_interval() {
    let authority = signing_generation(0);
    assert!(ValidatorEpochAuthorizationV1::genesis(&authority, 0).is_err());
    for mutation in 0..4 {
        let mut invalid = authority.clone();
        match mutation {
            0 => invalid.generation = 1,
            1 => invalid.validators[1] = invalid.validators[0].clone(),
            2 => invalid.validators.swap(0, 1),
            _ => {
                invalid.validators.pop();
            }
        }
        assert!(
            ValidatorEpochAuthorizationV1::genesis(&invalid, 10).is_err(),
            "mutation {mutation}"
        );
    }
    let foreign = signing_generation_with_seeds(0, 9);
    assert_eq!(
        genesis_authorization().validate_against_generation(&foreign),
        Err(ValidatorEpochAuthorizationErrorV1::InvalidField {
            field: "epoch_authorization.generation"
        })
    );
    let mut invalid = authority;
    invalid.validators.pop();
    assert_eq!(
        genesis_authorization().validate_against_generation(&invalid),
        Err(ValidatorEpochAuthorizationErrorV1::InvalidField {
            field: "validator_generation"
        })
    );
}

#[test]
fn authorization_rejects_unsupported_version_with_its_own_error() {
    let mut authorization = genesis_authorization();
    authorization.version = 2;
    assert_eq!(
        authorization.validate(),
        Err(ValidatorEpochAuthorizationErrorV1::UnsupportedVersion { actual: 2 })
    );
    assert!(authorization.authorization_id().is_err());
}

#[test]
fn scheduling_authorization_retains_keys_without_retaining_epoch() {
    let genesis = genesis_authorization();
    let retained = retained_authorization(&genesis);
    let retained_again = retained_authorization(&retained);
    retained.validate_successor(&genesis).unwrap();
    retained_again.validate_successor(&retained).unwrap();
    assert_eq!(retained.authority_id, genesis.authority_id);
    assert_eq!(retained_again.authority_generation, 0);
    assert_ne!(
        retained.authorization_id().unwrap(),
        genesis.authorization_id().unwrap()
    );
    assert_ne!(
        retained_again.authorization_id().unwrap(),
        retained.authorization_id().unwrap()
    );
    retained_again
        .validate_against_generation(&signing_generation(0))
        .unwrap();
}

#[test]
fn scheduling_authorization_rejects_gaps_stale_parent_and_relabeling() {
    let genesis = genesis_authorization();
    let current = retained_authorization(&genesis);
    let valid = retained_authorization(&current);
    for mutation in 0..8 {
        let mut invalid = valid;
        match mutation {
            0 => invalid.epoch += 1,
            1 => invalid.first_height += 1,
            2 => invalid.previous_authorization_id = genesis.authorization_id().unwrap(),
            3 => invalid.authority_generation += 1,
            4 => invalid.authority_id = [3; 32],
            5 => invalid.beacon = BeaconEpochBindingV1::Bootstrap,
            6 => {
                invalid.beacon = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
                    session_id: [9; 32],
                    transcript_hash: [8; 32],
                })
            }
            _ => invalid.transition_id = [5; 32],
        }
        assert!(
            invalid.validate_successor(&current).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn scheduling_authorization_activation_and_cancellation_bind_attempts() {
    let current = retained_authorization(&genesis_authorization());
    let mut successor = retained_authorization(&current);
    successor.decision = ValidatorEpochDecisionV1::Activate;
    successor.authority_generation = 1;
    let target = signing_generation_with_seeds(1, 5);
    successor.authority_id = target.generation_id().unwrap();
    assert!(successor.validate_successor(&current).is_err());
    successor.transition_id = [4; 32];
    successor.validate_successor(&current).unwrap();
    successor.validate_against_generation(&target).unwrap();
    let mut cancelled = retained_authorization(&current);
    cancelled.decision = ValidatorEpochDecisionV1::RetainAndCancel;
    cancelled.transition_id = [4; 32];
    cancelled.validate_successor(&current).unwrap();
    assert_ne!(
        cancelled.authorization_id().unwrap(),
        retained_authorization(&current).authorization_id().unwrap()
    );
    cancelled.transition_id = [0; 32];
    assert!(cancelled.validate().is_err());
}

#[test]
fn scheduling_authorization_roundtrips_canonical_norito() {
    let authorization = retained_authorization(&genesis_authorization());
    let bytes = authorization.encode();
    let decoded: ValidatorEpochAuthorizationV1 = Decode::decode(&mut bytes.as_slice()).unwrap();
    assert_eq!(decoded, authorization);
    let decoded = norito::json::value::from_value::<ValidatorEpochAuthorizationV1>(
        norito::json::to_value(&authorization).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded, authorization);
}
