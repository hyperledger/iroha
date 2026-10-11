//! Verify `JoinKaigi` instructions roundtrip through Norito encoding.
use iroha_crypto::Hash;
use iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1;
use iroha_data_model::{
    isi::{InstructionBox, kaigi::JoinKaigi},
    kaigi::{KaigiId, KaigiParticipantCommitment, KaigiParticipantNullifier},
    prelude::AccountId,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
#[test]
fn join_kaigi_roundtrip_preserves_optional_fields() {
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let call_id = KaigiId::new(
        domain_id.clone(),
        "kaigi".parse::<Name>().expect("call name"),
    );
    let participant =
        AccountId::parse_encoded("sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE")
            .expect("participant account id");
    let commitment = KaigiParticipantCommitment {
        commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x2A; 32]).unwrap(),
    };
    let nullifier = KaigiParticipantNullifier {
        digest: KaigiAuthorizationScalarV1::from_le_bytes([0x2B; 32]).unwrap(),
    };
    let join = JoinKaigi::new(
        call_id.clone(),
        participant.clone(),
        Some(commitment.clone()),
        Some(nullifier.clone()),
        Some(Hash::new([0xCC; Hash::LENGTH])),
        Some(vec![0x10, 0x20, 0x30]),
    );
    let boxed = iroha_data_model::isi::Instruction::into_instruction_box(Box::new(join.clone()));
    let encoded = norito::to_bytes(&boxed).expect("JoinKaigi should be serializable with norito");
    let decoded: InstructionBox =
        norito::decode_from_bytes(&encoded).expect("JoinKaigi should decode via norito");
    assert_eq!(
        decoded, boxed,
        "roundtrip should preserve instruction bytes"
    );
    let decoded_join = iroha_data_model::isi::Instruction::as_any(&*decoded)
        .downcast_ref::<JoinKaigi>()
        .expect("decoded JoinKaigi instruction");
    assert_eq!(decoded_join.call_id(), &call_id);
    assert_eq!(decoded_join.participant(), &participant);
    assert_eq!(decoded_join.commitment().as_ref(), Some(&commitment));
    assert_eq!(decoded_join.nullifier().as_ref(), Some(&nullifier));
    assert_eq!(
        *decoded_join.roster_root(),
        Some(Hash::new([0xCC; Hash::LENGTH]))
    );
    assert_eq!(
        decoded_join.proof().as_deref(),
        Some(&[0x10, 0x20, 0x30][..])
    );
}
