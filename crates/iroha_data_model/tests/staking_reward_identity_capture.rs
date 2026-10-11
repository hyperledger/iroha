//! Explicit current compiler capture for automatic staking reward model and claim codecs.
//!
//! The historical native report stays immutable. This maintenance target obtains
//! typed replacement identities and complete claim frames from the public model.

use std::{collections::BTreeMap, fmt::Debug};

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::staking::ClaimPublicLaneRewards,
    nexus::{
        PublicLaneFeeRewardClaimV1, PublicLaneMonetaryScopeV1, PublicLanePendingReward,
        PublicLaneRewardClaimPlanV1, PublicLaneValidatorRecord,
    },
};
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
use norito::{
    NoritoDeserialize, NoritoSchema, NoritoSerialize,
    json::{self, Value},
};

fn identity<T>() -> Value
where
    T: NoritoSchema + NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    let hash = hex::encode(norito::schema::identity::frame_hash::<T>());
    json::object([
        ("nominal", Value::String(T::nominal_name())),
        ("root", Value::String(T::frame_name())),
        ("serialize_hash", Value::String(hash.clone())),
        ("deserialize_hash", Value::String(hash)),
    ])
    .expect("current native identity")
}

fn frame<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + Debug + PartialEq,
{
    let bytes = norito::to_bytes(value).expect("encode current claim frame");
    let decoded: T = norito::decode_from_bytes(&bytes).expect("decode current claim frame");
    assert_eq!(&decoded, value);
    assert_eq!(
        norito::to_bytes(&decoded).expect("reencode current claim frame"),
        bytes
    );
    hex::encode(bytes)
}

fn account(seed: u8) -> AccountId {
    let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("deterministic checked capture account");
    AccountId::new(key.public_key().clone())
}

// Keep this value identical to isi::staking::tests::reward_claim_fixture.
fn claim() -> ClaimPublicLaneRewards {
    let definition = AssetDefinitionId::from_uuid_bytes([
        0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd, 0xcd,
        0x2f,
    ])
    .expect("canonical fixture asset definition");
    ClaimPublicLaneRewards {
        lane_id: LaneId::SINGLE,
        account: account(0x11),
        claim_plan: PublicLaneRewardClaimPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(NetworkId::from_genesis_hash(
                HashOf::from_untyped_unchecked(Hash::new(b"candidate-network")),
            )),
            valid_until_height: 13,
            fee_claim: PublicLaneFeeRewardClaimV1 {
                lifecycle_seal: [0x81; 32],
                beneficiary_id: account(0x11),
                beneficiary_revision: 3,
                source_asset: AssetId::new(definition.clone(), account(0x22)),
                destination_asset: AssetId::new(definition, account(0x11)),
                amount: Quantity::from(7_u64),
                expected_claim_sequence: 17,
            },
        },
    }
}

#[test]
#[ignore = "explicit maintenance capture of current reward model identities and claim frames"]
fn print_staking_reward_identity_capture() {
    let rows = Value::Array(vec![
        identity::<PublicLaneValidatorRecord>(),
        identity::<PublicLanePendingReward>(),
    ]);
    println!(
        "STAKING_REWARD_IDENTITIES={}",
        json::to_json(&rows).expect("identity JSON")
    );
    let value = claim();
    assert!(value.claim_plan().has_canonical_shape(value.account()));
    let hash = hex::encode(norito::schema::identity::frame_hash::<ClaimPublicLaneRewards>());
    let record = json::object([
        (
            "nominal",
            Value::String(ClaimPublicLaneRewards::nominal_name()),
        ),
        ("serialize_hash", Value::String(hash.clone())),
        ("deserialize_hash", Value::String(hash)),
        ("frame", Value::String(frame(&value))),
        ("vector_frame", Value::String(frame(&vec![value.clone()]))),
        ("option_frame", Value::String(frame(&Some(value.clone())))),
        (
            "map_frame",
            Value::String(frame(&BTreeMap::from([(7_u8, value)]))),
        ),
    ])
    .expect("current complete claim record");
    println!(
        "STAKING_CLAIM_FIXTURE_ROW={}",
        json::to_json(&record).expect("claim JSON")
    );
}
