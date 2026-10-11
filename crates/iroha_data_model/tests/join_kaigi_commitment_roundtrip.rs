//! Verifies `JoinKaigi` preserves canonical raw Pasta commitment bytes.
use iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1;
use iroha_data_model::{
    account::AccountId,
    isi::{InstructionBox, kaigi::JoinKaigi},
    kaigi::{KaigiId, KaigiParticipantCommitment},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use norito::core::DeserializePayload;
use std::str::FromStr;
#[test]
fn join_kaigi_preserves_canonical_raw_commitment() {
    let call = KaigiId::new(
        DomainId::try_new("wonderland", "universal").expect("domain"),
        Name::from_str("weekly-sync").expect("call name"),
    );
    let participant =
        AccountId::parse_encoded("sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE")
            .expect("account id");
    let commitment = KaigiAuthorizationScalarV1::from_le_bytes([0x24; 32]).unwrap();
    let join = JoinKaigi::new(
        call,
        participant,
        Some(KaigiParticipantCommitment { commitment }),
        None,
        None,
        None,
    );
    let instruction =
        iroha_data_model::isi::Instruction::into_instruction_box(Box::new(join.clone()));
    let bytes = norito::core::to_bytes(&instruction).expect("serialize");
    let archived = norito::core::from_bytes::<InstructionBox>(&bytes).expect("from bytes");
    let decoded = InstructionBox::try_deserialize(archived).expect("deserialize");
    assert_eq!(decoded.as_any().downcast_ref::<JoinKaigi>(), Some(&join));
}

#[test]
fn join_kaigi_rejects_retired_hash_scalar_json() {
    let literal = "\"hash:1111111111111111111111111111111111111111111111111111111111111111#4667\"";
    assert!(norito::json::from_str::<KaigiAuthorizationScalarV1>(literal).is_err());
}
