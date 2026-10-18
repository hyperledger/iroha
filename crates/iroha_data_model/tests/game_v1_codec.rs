//! Independent Rust/browser compact-Norito parity for generic game authorization.

use iroha_crypto::{Hash, PublicKey};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    execution_proofs::{
        ExecutionProofEnvelopeV1, RaceDnfEventV1, RaceProverRequestV1, RaceResultV1,
    },
    game::{
        GameAdmissionBodyV1, GameCheckpointV1, GameInputRevealV1, GameItemStakeV1, GameManifestV1,
        GameOutcomeV1, GamePayoutClaimV1, GameTranscriptV1, SignedGameCheckpointV1,
        game_message_hash_v1,
    },
    isi::game::{ClaimGamePayoutV1, JoinGameSessionV1, OpenGameSessionV1, StakeGameItemV1},
};
use norito::{
    codec::Encode,
    json::{self, JsonDeserialize, Value},
};

#[derive(norito::derive::JsonDeserialize)]
struct Fixtures {
    version: u16,
    network_id: NetworkId,
    vectors: Vec<Vector>,
}
#[derive(norito::derive::JsonDeserialize)]
struct Vector {
    name: String,
    value: Value,
    encoded_hex: String,
    framed_hex: Option<String>,
    domain: Option<String>,
    gameplay_digest_hex: Option<String>,
    case: Option<String>,
    source_proof_sha256: Option<String>,
}
#[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
struct CommitmentBody {
    session_id: Hash,
    epoch: u64,
    start_tick: u32,
    parent_transcript_root: Hash,
    commitments: Vec<Hash>,
}
#[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
struct ChallengeBody {
    session_id: Hash,
    epoch: u64,
    slot: u8,
}

#[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
struct AdmissionCommitment {
    session_id: Hash,
    admission: GameAdmissionBodyV1,
}
#[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
struct InvitationBody {
    session_id: Hash,
    wallet: AccountId,
    input_key: PublicKey,
    application_data: Vec<u8>,
}
fn check_body<T: Encode + norito::NoritoSerialize>(body: &T, vector: &Vector, network: &NetworkId) {
    assert_eq!(
        hex::encode_upper(body.encode()),
        vector.encoded_hex,
        "{} bytes",
        vector.name
    );
    if let Some(framed) = &vector.framed_hex {
        assert_eq!(
            hex::encode_upper(norito::to_bytes(body).expect("native framed fixture")),
            *framed,
            "{} framed bytes and schema identity",
            vector.name
        );
    }
    if let Some(domain) = &vector.domain {
        let digest = game_message_hash_v1(network, domain, body);
        assert_eq!(
            hex::encode_upper(digest.as_ref()),
            vector.gameplay_digest_hex.as_deref().unwrap(),
            "{} digest",
            vector.name
        );
        assert_ne!(
            digest,
            game_message_hash_v1(network, "different-domain", body),
            "signature domain separation"
        );
    }
}
fn check<T: Encode + JsonDeserialize + norito::NoritoSerialize>(
    vector: &Vector,
    network: &NetworkId,
) {
    let body: T = json::from_value(vector.value.clone()).expect(&vector.name);
    check_body(&body, vector, network);
}
#[test]
fn browser_game_v1_wire_and_gameplay_hash_vectors_match_native() {
    let fixtures: Fixtures = json::from_str(include_str!(
        "../../../javascript/iroha_js/test/fixtures/game-v1-codec.json"
    ))
    .expect("public browser fixtures");
    assert_eq!(fixtures.version, 1);
    assert_eq!(fixtures.vectors.len(), 24);
    for vector in fixtures.vectors {
        if let Some(source) = &vector.source_proof_sha256 {
            assert_eq!(source.len(), 64);
            assert!(source.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(vector.case.as_ref().is_some_and(|case| !case.is_empty()));
        }
        match vector.name.as_str() {
            "GameManifestV1" => check::<GameManifestV1>(&vector, &fixtures.network_id),
            "RaceProverRequestV1" => {
                check::<RaceProverRequestV1>(&vector, &fixtures.network_id);
                let body: RaceProverRequestV1 = json::from_value(vector.value.clone()).unwrap();
                let json_body = json::to_value(&body).unwrap();
                assert_eq!(
                    json::from_value::<RaceProverRequestV1>(json_body).unwrap(),
                    body
                );
                let framed = norito::to_bytes(&body).unwrap();
                assert_eq!(
                    norito::decode_from_bytes::<RaceProverRequestV1>(&framed).unwrap(),
                    body
                );
            }
            "GameOutcomeV1" => check::<GameOutcomeV1>(&vector, &fixtures.network_id),
            "RaceResultV1" => check::<RaceResultV1>(&vector, &fixtures.network_id),
            "RaceDnfEventV1" => check::<RaceDnfEventV1>(&vector, &fixtures.network_id),
            "GamePayoutClaimV1" => check::<GamePayoutClaimV1>(&vector, &fixtures.network_id),
            "ClaimGamePayoutV1" => check::<ClaimGamePayoutV1>(&vector, &fixtures.network_id),
            "StakeGameItemV1" => check::<StakeGameItemV1>(&vector, &fixtures.network_id),
            "GameItemStakeV1" => check::<GameItemStakeV1>(&vector, &fixtures.network_id),
            "GameAdmissionBodyV1" => {
                let body: GameAdmissionBodyV1 = json::from_value(vector.value.clone()).unwrap();
                body.validate().expect("canonical admission fixture");
                check_body(&body, &vector, &fixtures.network_id);
            }
            "GameAdmissionCommitmentV1" => {
                let b: AdmissionCommitment = json::from_value(vector.value.clone()).unwrap();
                b.admission.validate().expect("canonical admission fixture");
                check_body(
                    &(b.session_id, b.admission.clone()),
                    &vector,
                    &fixtures.network_id,
                );
                assert_eq!(
                    hex::encode_upper(
                        iroha_data_model::game::game_roster_hash_v1(
                            &fixtures.network_id,
                            &b.session_id,
                            &b.admission,
                        )
                        .as_ref()
                    ),
                    vector.gameplay_digest_hex.as_deref().unwrap()
                );
            }
            "GameInvitationBodyV1" => {
                let b: InvitationBody = json::from_value(vector.value.clone()).unwrap();
                check_body(
                    &(b.session_id, b.wallet, b.input_key, b.application_data),
                    &vector,
                    &fixtures.network_id,
                );
            }
            "OpenGameSessionV1" => check::<OpenGameSessionV1>(&vector, &fixtures.network_id),
            "JoinGameSessionV1" => check::<JoinGameSessionV1>(&vector, &fixtures.network_id),
            "GameCheckpointV1" => check::<GameCheckpointV1>(&vector, &fixtures.network_id),
            "GameInputRevealV1" => check::<GameInputRevealV1>(&vector, &fixtures.network_id),
            "SignedGameCheckpointV1" => {
                check::<SignedGameCheckpointV1>(&vector, &fixtures.network_id)
            }
            "GameTranscriptV1" => check::<GameTranscriptV1>(&vector, &fixtures.network_id),
            "ExecutionProofEnvelopeV1" => {
                check::<ExecutionProofEnvelopeV1>(&vector, &fixtures.network_id)
            }
            "GameCommitmentSetBodyV1" => {
                let b: CommitmentBody = json::from_value(vector.value.clone()).unwrap();
                check_body(
                    &(
                        b.session_id,
                        b.epoch,
                        b.start_tick,
                        b.parent_transcript_root,
                        b.commitments,
                    ),
                    &vector,
                    &fixtures.network_id,
                );
            }
            "GameChallengeBodyV1" => {
                let b: ChallengeBody = json::from_value(vector.value.clone()).unwrap();
                check_body(
                    &(b.session_id, b.epoch, b.slot),
                    &vector,
                    &fixtures.network_id,
                );
            }
            other => panic!("unrecognized public fixture {other}"),
        }
    }
}

#[test]
fn every_generic_game_instruction_roundtrips_through_the_native_registry() {
    fn value<T: JsonDeserialize>(fixtures: &Fixtures, name: &str) -> T {
        json::from_value(
            fixtures
                .vectors
                .iter()
                .find(|vector| vector.name == name)
                .expect("shared fixture")
                .value
                .clone(),
        )
        .expect(name)
    }
    use iroha_crypto::Signature;
    use iroha_data_model::{
        game::{GameCommitmentSetV1, GameInputCommitmentV1},
        isi::{InstructionBox, game::*},
    };
    let fixtures: Fixtures = json::from_str(include_str!(
        "../../../javascript/iroha_js/test/fixtures/game-v1-codec.json"
    ))
    .unwrap();
    let open: OpenGameSessionV1 = value(&fixtures, "OpenGameSessionV1");
    let session_id = *open.session_id();
    let profile_id = open.manifest().profile_id;
    let join: JoinGameSessionV1 = value(&fixtures, "JoinGameSessionV1");
    let checkpoint: SignedGameCheckpointV1 = value(&fixtures, "SignedGameCheckpointV1");
    let proof: ExecutionProofEnvelopeV1 = value(&fixtures, "ExecutionProofEnvelopeV1");
    let signature = Signature::from_bytes(&[17; 64]);
    let cases: Vec<(&str, InstructionBox)> = vec![
        (
            "OpenGameSessionV1",
            OpenGameSessionV1::new(
                session_id,
                open.manifest().clone(),
                open.asset_definition().clone(),
                open.stake().clone(),
                *open.join_deadline_height(),
            )
            .into(),
        ),
        (
            "JoinGameSessionV1",
            JoinGameSessionV1 {
                session_id: *join.session_id(),
                input_key: join.input_key().clone(),
                application_data: join.application_data().clone(),
                resources: join.resources().clone(),
                invitation: join.invitation().clone(),
                expected_manifest_hash: *join.expected_manifest_hash(),
                expected_asset_definition: join.expected_asset_definition().clone(),
                expected_stake: join.expected_stake().clone(),
            }
            .into(),
        ),
        (
            "StartGameSessionV1",
            StartGameSessionV1::new(session_id).into(),
        ),
        (
            "CommitGameCheckpointV1",
            CommitGameCheckpointV1::new(
                session_id,
                checkpoint.clone(),
                Some(GameCommitmentSetV1 {
                    session_id,
                    epoch: checkpoint.checkpoint.epoch,
                    start_tick: checkpoint.checkpoint.tick,
                    parent_transcript_root: checkpoint.checkpoint.transcript_root,
                    commitments: vec![Hash::new(b"commitment")],
                    signatures: checkpoint.signatures.clone(),
                }),
            )
            .into(),
        ),
        (
            "ChallengeGameSessionV1",
            ChallengeGameSessionV1::new(session_id, 5, 0, signature.clone()).into(),
        ),
        (
            "CommitGameInputsV1",
            CommitGameInputsV1::new(GameInputCommitmentV1 {
                session_id,
                epoch: 5,
                start_tick: 30,
                slot: 0,
                commitment: Hash::new(b"committed-inputs"),
                signature,
            })
            .into(),
        ),
        (
            "RevealGameInputsV1",
            RevealGameInputsV1::new(value(&fixtures, "GameInputRevealV1")).into(),
        ),
        (
            "AdvanceGameDeadlineV1",
            AdvanceGameDeadlineV1::new(session_id).into(),
        ),
        (
            "SettleGameSessionV1",
            SettleGameSessionV1::new(session_id, proof.clone(), value(&fixtures, "GameOutcomeV1"))
                .into(),
        ),
        (
            "ExpireGameSessionV1",
            ExpireGameSessionV1::new(session_id).into(),
        ),
        (
            "ClaimGamePayoutV1",
            ClaimGamePayoutV1::new(
                session_id,
                0,
                iroha_data_model::account::AccountId::new(join.input_key().clone()),
                open.stake().clone(),
            )
            .into(),
        ),
        (
            "StakeGameItemV1",
            StakeGameItemV1::new(
                session_id,
                "skin$session.universal".parse().unwrap(),
                Hash::new(b"manifest"),
            )
            .into(),
        ),
        (
            "RegisterExecutionProofProfileV1",
            RegisterExecutionProofProfileV1::new(profile_id).into(),
        ),
        (
            "VerifyExecutionProofV1",
            VerifyExecutionProofV1::new(proof).into(),
        ),
    ];
    for (name, original) in cases {
        let expected_wire_id = format!("iroha.instruction.v1::game::{name}");
        assert_eq!(
            iroha_data_model::isi::instruction_wire_id(&original),
            Some(expected_wire_id.as_str())
        );
        let bytes = norito::to_bytes(&original).expect(name);
        let restored: InstructionBox = norito::decode_from_bytes(&bytes).expect(name);
        assert_eq!(original.id(), restored.id(), "{name} registry identity");
        assert_eq!(
            bytes,
            norito::to_bytes(&restored).unwrap(),
            "{name} complete payload"
        );
    }
}

#[test]
fn join_requires_explicit_resources_and_signed_terms_and_rejects_obsolete_payloads() {
    // An obsolete seven-field body may carry exact debit terms, but has no typed
    // equipment authorization. The sole first-release decoder must reject it.
    #[derive(Encode)]
    struct MissingResources {
        session_id: Hash,
        input_key: PublicKey,
        application_data: Vec<u8>,
        invitation: Option<iroha_crypto::Signature>,
        expected_manifest_hash: Hash,
        expected_asset_definition: iroha_data_model::asset::AssetDefinitionId,
        expected_stake: iroha_primitives::numeric::Quantity,
    }
    use norito::codec::Decode;
    let fixtures: Fixtures = json::from_str(include_str!(
        "../../../javascript/iroha_js/test/fixtures/game-v1-codec.json"
    ))
    .unwrap();
    let value = fixtures
        .vectors
        .iter()
        .find(|vector| vector.name == "JoinGameSessionV1")
        .unwrap()
        .value
        .clone();
    let join: JoinGameSessionV1 = json::from_value(value.clone()).unwrap();
    let open: OpenGameSessionV1 = json::from_value(
        fixtures
            .vectors
            .iter()
            .find(|vector| vector.name == "OpenGameSessionV1")
            .unwrap()
            .value
            .clone(),
    )
    .unwrap();
    assert_eq!(
        *join.expected_manifest_hash(),
        game_message_hash_v1(&fixtures.network_id, "session-manifest", open.manifest())
    );
    assert_eq!(join.expected_asset_definition(), open.asset_definition());
    assert_eq!(join.expected_stake(), open.stake());
    for required in [
        "resources",
        "expected_manifest_hash",
        "expected_asset_definition",
        "expected_stake",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(required);
        assert!(
            json::from_value::<JoinGameSessionV1>(missing).is_err(),
            "missing {required}"
        );
    }
    let encoded = join.encode();
    let mut input = encoded.as_slice();
    let decoded = JoinGameSessionV1::decode(&mut input).unwrap();
    assert!(input.is_empty());
    assert_eq!(decoded.encode(), encoded);
    let framed = norito::to_bytes(&join).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<JoinGameSessionV1>(&framed)
            .unwrap()
            .encode(),
        encoded
    );

    let obsolete = MissingResources {
        session_id: *join.session_id(),
        input_key: join.input_key().clone(),
        application_data: join.application_data().clone(),
        invitation: join.invitation().clone(),
        expected_manifest_hash: *join.expected_manifest_hash(),
        expected_asset_definition: join.expected_asset_definition().clone(),
        expected_stake: join.expected_stake().clone(),
    }
    .encode();
    assert!(JoinGameSessionV1::decode(&mut obsolete.as_slice()).is_err());
    assert!(
        <JoinGameSessionV1 as norito::core::DecodeFromSlice>::decode_from_slice(&obsolete).is_err()
    );
}

#[test]
fn application_outcome_contains_no_ledger_receipt_or_settlement_height() {
    let outcome = GameOutcomeV1 {
        terminal_tick: 180,
        winner_slots: vec![1, 3],
        result: vec![7, 8, 9],
    };
    let json = json::to_value(&outcome).unwrap();
    let mut fields = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(fields, vec!["result", "terminal_tick", "winner_slots"]);
}

#[path = "full_race_payload_codec.rs"]
mod full_race_payload_codec;

/// Export only from canonical semantic seed values through actual native codecs.
/// This never accepts JavaScript bytes as native provenance.
#[test]
#[ignore = "explicit native fixture export: set SORA_CARS_GAME_FIXTURE_SEED and SORA_CARS_GAME_FIXTURE_OUTPUT"]
fn export_canonical_game_wire_fixtures_from_semantic_seed() {
    use iroha_data_model::game_resources::*;
    use std::io::Write as _;
    struct NativeParts {
        value: Value,
        bare: Vec<u8>,
        framed: Vec<u8>,
        digest: Option<Hash>,
    }
    fn parts<T: Encode + norito::NoritoSerialize>(
        body: &T,
        value: Value,
        domain: Option<&str>,
        network: &NetworkId,
    ) -> NativeParts {
        NativeParts {
            value,
            bare: body.encode(),
            framed: norito::to_bytes(body).expect("native framed fixture"),
            digest: domain.map(|domain| game_message_hash_v1(network, domain, body)),
        }
    }
    let seed_path = std::env::var_os("SORA_CARS_GAME_FIXTURE_SEED").expect("semantic seed path");
    let output_path =
        std::env::var_os("SORA_CARS_GAME_FIXTURE_OUTPUT").expect("native output path");
    let seed: Value = json::from_slice(&std::fs::read(seed_path).expect("read semantic seed"))
        .expect("semantic seed JSON");
    let network: NetworkId = json::from_value(seed["network_id"].clone()).expect("seed network");
    assert_eq!(seed["version"].as_u64(), Some(1));
    let mut rows = Vec::new();
    for source in seed["vectors"].as_array().expect("semantic vectors") {
        let name = source["name"].as_str().expect("fixture type");
        let domain = source.get("domain").and_then(Value::as_str);
        let value = &source["value"];
        macro_rules! native {
            ($ty:ty) => {{
                let body: $ty = json::from_value(value.clone()).expect(name);
                parts(
                    &body,
                    json::to_value(&body).expect("canonical native JSON"),
                    domain,
                    &network,
                )
            }};
        }
        let encoded = match name {
            "GameManifestV1" => native!(GameManifestV1),
            "RaceProverRequestV1" => native!(RaceProverRequestV1),
            "GameOutcomeV1" => native!(GameOutcomeV1),
            "RaceResultV1" => native!(RaceResultV1),
            "RaceDnfEventV1" => native!(RaceDnfEventV1),
            "GamePayoutClaimV1" => native!(GamePayoutClaimV1),
            "ClaimGamePayoutV1" => native!(ClaimGamePayoutV1),
            "StakeGameItemV1" => native!(StakeGameItemV1),
            "GameItemStakeV1" => native!(GameItemStakeV1),
            "GameAdmissionBodyV1" => native!(GameAdmissionBodyV1),
            "OpenGameSessionV1" => native!(OpenGameSessionV1),
            "JoinGameSessionV1" => native!(JoinGameSessionV1),
            "GameCheckpointV1" => native!(GameCheckpointV1),
            "GameInputRevealV1" => native!(GameInputRevealV1),
            "SignedGameCheckpointV1" => native!(SignedGameCheckpointV1),
            "GameTranscriptV1" => native!(GameTranscriptV1),
            "ExecutionProofEnvelopeV1" => native!(ExecutionProofEnvelopeV1),
            "GameResourceReturnPolicyV1" => native!(GameResourceReturnPolicyV1),
            "GameResourceReservationClauseV1" => native!(GameResourceReservationClauseV1),
            "GameResourceRequirementV1" => native!(GameResourceRequirementV1),
            "GameResourceReservationRecordV1" => native!(GameResourceReservationRecordV1),
            "GameResourceReservationSetV1" => native!(GameResourceReservationSetV1),
            "GameAdmissionCommitmentV1" => {
                assert_eq!(domain, Some("roster"));
                let b: AdmissionCommitment = json::from_value(value.clone()).expect(name);
                b.admission.validate().expect("bounded canonical admission");
                let canonical = json::to_value(&b).unwrap();
                parts(&(b.session_id, b.admission), canonical, domain, &network)
            }
            "GameInvitationBodyV1" => {
                let b: InvitationBody = json::from_value(value.clone()).expect(name);
                let canonical = json::to_value(&b).unwrap();
                parts(
                    &(b.session_id, b.wallet, b.input_key, b.application_data),
                    canonical,
                    domain,
                    &network,
                )
            }
            "GameCommitmentSetBodyV1" => {
                let b: CommitmentBody = json::from_value(value.clone()).expect(name);
                let canonical = json::to_value(&b).unwrap();
                parts(
                    &(
                        b.session_id,
                        b.epoch,
                        b.start_tick,
                        b.parent_transcript_root,
                        b.commitments,
                    ),
                    canonical,
                    domain,
                    &network,
                )
            }
            "GameChallengeBodyV1" => {
                let b: ChallengeBody = json::from_value(value.clone()).expect(name);
                let canonical = json::to_value(&b).unwrap();
                parts(
                    &(b.session_id, b.epoch, b.slot),
                    canonical,
                    domain,
                    &network,
                )
            }
            other => panic!("unrecognized canonical fixture {other}"),
        };
        let mut row = norito::json!({
            "name": name,
            "value": (encoded.value),
            "encoded_hex": (hex::encode_upper(encoded.bare)),
            "framed_hex": (hex::encode_upper(encoded.framed)),
        });
        let object = row.as_object_mut().unwrap();
        if let Some(domain) = domain {
            object.insert("domain".into(), domain.into());
            object.insert(
                "gameplay_digest_hex".into(),
                hex::encode_upper(encoded.digest.unwrap().as_ref()).into(),
            );
        }
        for metadata in ["case", "source_proof_sha256"] {
            if let Some(value) = source.get(metadata) {
                object.insert(metadata.into(), value.clone());
            }
        }
        rows.push(row);
    }
    let output = norito::json!({"version": 1, "network_id": network, "vectors": rows});
    let bytes = json::to_vec(&output).expect("native fixture JSON");
    // A mistaken path must not silently replace retained evidence or live fixtures.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("fresh native fixture output");
    file.write_all(&bytes).expect("write exact native fixtures");
    file.sync_all().expect("flush exact native fixtures");
}

#[path = "game_resources_v1_codec.rs"]
mod resource_wire;
