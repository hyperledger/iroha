//! Strict native JSON projections for public-lane staking and treasury rewards.
//!
//! The model owns quantities, hashes, signatures, and canonical account strings.
//! Core separately verifies consent, custody, election readiness, and authority.

use iroha_data_model::isi::{InstructionBox, staking::*};
use norito::json::{self, Value};

use crate::{CodecError, CodecErrorKind, CodecResult};

fn safe_json_numbers(value: &Value) -> CodecResult<()> {
    match value {
        Value::Number(number) => {
            if number
                .as_u64()
                .is_some_and(|value| value > crate::json_u64::MAX_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|value| value < crate::json_u64::MIN_SAFE_INTEGER)
            {
                return Err(CodecError::new(
                    CodecErrorKind::InvalidArgument,
                    "staking JSON integer exceeds the JavaScript safe-integer range",
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                safe_json_numbers(value)?;
            }
        }
        Value::Object(fields) => {
            for value in fields.values() {
                safe_json_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

macro_rules! staking_codec {
    ($($ty:ident),+ $(,)?) => {
        pub fn from_json(value: &Value) -> Option<CodecResult<InstructionBox>> {
            let Value::Object(fields) = value else { return None; };
            $(if let Some(payload) = fields.get(stringify!($ty)) {
                return Some((|| {
                    crate::exact_json_object_fields(value, &[stringify!($ty)], "staking instruction envelope")?;
                    safe_json_numbers(payload)?;
                    let instruction: $ty = crate::strict_typed_instruction(payload, stringify!($ty))?;
                    Ok(instruction.into())
                })());
            })+
            None
        }
        pub fn to_json(instruction: &InstructionBox) -> Option<CodecResult<Value>> {
            $(if let Some(typed) = instruction.as_any().downcast_ref::<$ty>() {
                return Some((|| {
                    let payload = json::to_value(typed).map_err(crate::codec_error)?;
                    safe_json_numbers(&payload)?;
                    let decoded: $ty = crate::strict_typed_instruction(&payload, stringify!($ty))?;
                    if norito::encode_canonical(typed).map_err(crate::codec_error)?
                        != norito::encode_canonical(&decoded).map_err(crate::codec_error)? {
                        return Err(CodecError::failure("staking JSON changes canonical Norito bytes"));
                    }
                    Ok(crate::instruction_envelope(stringify!($ty), payload))
                })());
            })+
            None
        }
        pub fn is_staking_instruction(instruction: &InstructionBox) -> bool {
            false $(|| instruction.as_any().is::<$ty>())+
        }
    };
}
staking_codec!(
    RegisterPublicLaneCandidate,
    RegisterPublicLaneValidator,
    RebindPublicLaneValidatorPeer,
    ActivatePublicLaneValidator,
    ExitPublicLaneValidator,
    BondPublicLaneStake,
    SchedulePublicLaneUnbond,
    FinalizePublicLaneUnbond,
    SlashPublicLaneValidator,
    ClaimPublicLaneRewards,
);

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
        nexus::{
            PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
            PublicLaneMonetaryRegistrationV1, PublicLaneMonetaryScopeV1,
        },
    };
    use iroha_model_base::{domain::DomainId, metadata::Metadata, peer::PeerId, topology::LaneId};
    use iroha_primitives::numeric::Quantity;

    fn candidate() -> RegisterPublicLaneCandidate {
        let account_key = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519).unwrap();
        let peer_key = KeyPair::try_from_seed(vec![0x72; 32], Algorithm::BlsNormal).unwrap();
        let owner = AccountId::new(account_key.public_key().clone());
        let escrow_key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519).unwrap();
        let escrow = AccountId::new(escrow_key.public_key().clone());
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("staking", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"codec-candidate-network",
        )));
        let monetary_plan = PublicLaneMonetaryPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(network_id),
            valid_until_height: 100,
            source_asset: AssetId::new(definition.clone(), owner.clone()),
            destination_asset: AssetId::new(definition, escrow),
            amount: Quantity::from(1000_u64),
            precondition: PublicLaneMonetaryPreconditionV1::Registration(
                PublicLaneMonetaryRegistrationV1 {
                    activation_height: 101,
                },
            ),
        };
        let registration = RegisterPublicLaneValidator::new(
            LaneId::new(42),
            owner.clone(),
            PeerId::new(peer_key.public_key().clone()),
            owner.clone(),
            Quantity::from(1000_u64),
            Metadata::default(),
            monetary_plan,
        );
        let payload = PublicLaneCandidateAuthorization::new(network_id, registration.clone(), 101);
        RegisterPublicLaneCandidate {
            registration,
            activation_height: 101,
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(peer_key.private_key())
                .unwrap(),
            peer_signature: SignatureOf::try_new(peer_key.private_key(), &payload).unwrap(),
        }
    }

    #[test]
    fn staking_candidate_json_and_frame_preserve_exact_native_consent() {
        let original: InstructionBox = candidate().into();
        let json = crate::instruction_to_json_value(&original).unwrap();
        let restored = crate::value_to_instruction(json.clone()).unwrap();
        assert_eq!(
            norito::encode_canonical(&original).unwrap(),
            norito::encode_canonical(&restored).unwrap()
        );
        assert!(is_staking_instruction(&restored));
        let text = norito::json::to_json(&json).unwrap();
        let frame = crate::encode_instruction_frame(&text, 753).unwrap();
        let decoded = crate::decode_instruction_frame(&frame, 753).unwrap();
        assert_eq!(norito::json::from_str::<Value>(&decoded).unwrap(), json);
    }

    #[test]
    fn staking_json_rejects_manual_reward_publication() {
        let value = json::json!({"RecordPublicLaneRewards": {}});
        assert!(from_json(&value).is_none());
        assert!(crate::value_to_instruction(value).is_err());
    }

    #[test]
    fn staking_json_rejects_unknown_fields_and_unsafe_integer_values() {
        let original: InstructionBox = candidate().into();
        let mut value = crate::instruction_to_json_value(&original).unwrap();
        let Value::Object(fields) = &mut value else {
            unreachable!()
        };
        let Value::Object(payload) = fields.get_mut("RegisterPublicLaneCandidate").unwrap() else {
            unreachable!()
        };
        payload.insert("unexpected".into(), Value::Bool(true));
        assert!(crate::value_to_instruction(value).is_err());
        assert!(safe_json_numbers(&Value::from(crate::json_u64::MAX_SAFE_INTEGER + 1)).is_err());
        assert!(safe_json_numbers(&Value::from(crate::json_u64::MIN_SAFE_INTEGER - 1)).is_err());
    }

    #[test]
    fn staking_candidate_json_requires_the_complete_signed_monetary_plan() {
        let candidate = candidate();
        let original: InstructionBox = candidate.clone().into();
        let value = crate::instruction_to_json_value(&original).unwrap();
        for replacement in [
            None,
            Some(Value::Null),
            Some(Value::Object(json::Map::new())),
        ] {
            let mut altered = value.clone();
            let registration = altered
                .as_object_mut()
                .unwrap()
                .get_mut("RegisterPublicLaneCandidate")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .get_mut("registration")
                .unwrap()
                .as_object_mut()
                .unwrap();
            registration.remove("monetary_plan");
            if let Some(replacement) = replacement {
                registration.insert("monetary_plan".into(), replacement);
            }
            assert!(crate::value_to_instruction(altered).is_err());
        }
        let restored = crate::value_to_instruction(value).unwrap();
        let restored = restored
            .as_any()
            .downcast_ref::<RegisterPublicLaneCandidate>()
            .unwrap();
        assert_eq!(
            restored.registration.monetary_plan,
            candidate.registration.monetary_plan
        );
        let PublicLaneMonetaryScopeV1::Network(network_id) =
            restored.registration.monetary_plan.network_scope
        else {
            panic!("candidate must authorize its exact network");
        };
        let mut authorization = PublicLaneCandidateAuthorization::new(
            network_id,
            restored.registration.clone(),
            restored.activation_height,
        );
        restored
            .peer_signature
            .verify(restored.registration.peer_id.public_key(), &authorization)
            .unwrap();
        authorization.registration.monetary_plan.destination_asset = authorization
            .registration
            .monetary_plan
            .source_asset
            .clone();
        assert!(
            restored
                .peer_signature
                .verify(restored.registration.peer_id.public_key(), &authorization)
                .is_err()
        );
    }
}
