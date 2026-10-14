//! Native-origin wire fixtures for explicit equipment authorization and custody records.
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, derive_non_signing_ed25519_public_key};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    block::BlockHeader,
    events::data::game::GameSessionEventV1,
    game::*,
    isi::game::JoinGameSessionV1,
    nft::NftId,
    nft_market::{NftCustodyPurposeV1, NftCustodyRecordV1},
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use norito::{
    codec::{Decode, Encode},
    json,
};

#[test]
#[ignore = "explicit native export: set SORA_CARS_RESOURCE_FIXTURE_OUTPUT to a fresh output file"]
fn export_resource_admission_wire_fixtures() {
    let output = std::env::var_os("SORA_CARS_RESOURCE_FIXTURE_OUTPUT").expect("fresh output path");
    assert!(
        !std::path::Path::new(&output).exists(),
        "never overwrite retained native evidence"
    );
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"resource-codec-fixture-network"),
    ));
    let session_id = Hash::new(b"resource-codec-fixture-session");
    let key = KeyPair::try_from_seed(vec![41; 32], Algorithm::Ed25519).unwrap();
    let owner = AccountId::new(key.public_key().clone());
    let nft_id: NftId = "engine$equipment.universal".parse().unwrap();
    let metadata_hash = Hash::new(b"native resource fixture metadata");
    let role_id = Hash::new(b"native resource fixture role");
    let policy = GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal;
    let purpose = NftCustodyPurposeV1::GameResource;
    let custody = AccountId::new(derive_non_signing_ed25519_public_key(
        b"iroha:nft:custody:v1",
        &[
            network.as_bytes(),
            session_id.as_ref(),
            &purpose.encode(),
            &nft_id.encode(),
        ],
    ));
    let clause = GameResourceReservationClauseV1 {
        nft_id: nft_id.clone(),
        expected_metadata_hash: metadata_hash,
        role_id,
        policy,
    };
    let requirement = GameResourceRequirementV1 {
        nft_id: nft_id.clone(),
        expected_metadata_hash: metadata_hash,
        role_id,
        policy,
    };
    let open = GameResourceReservationRecordV1 {
        slot: 0,
        nft_id: nft_id.clone(),
        metadata_hash,
        role_id,
        policy,
        original_owner: owner.clone(),
        custody: custody.clone(),
        reserved_at_height: 10,
        released_at_height: None,
    };
    let terminal = GameResourceReservationRecordV1 {
        released_at_height: Some(40),
        ..open.clone()
    };
    let open_set = GameResourceReservationSetV1 {
        version: 1,
        network_id: network,
        session_id,
        records: vec![open.clone()],
    };
    let terminal_set = GameResourceReservationSetV1 {
        records: vec![terminal.clone()],
        ..open_set.clone()
    };
    validate_resource_clauses_v1(std::slice::from_ref(&clause)).unwrap();
    match_resource_requirements_v1(
        std::slice::from_ref(&clause),
        std::slice::from_ref(&requirement),
    )
    .unwrap();
    open_set
        .validate_for_owners(std::slice::from_ref(&owner))
        .unwrap();
    terminal_set
        .validate_for_owners(std::slice::from_ref(&owner))
        .unwrap();
    let native_open = NftCustodyRecordV1 {
        version: 1,
        network_id: network,
        reservation_id: session_id,
        purpose,
        nft_id,
        custody,
        original_owner: owner.clone(),
        metadata_hash,
        released_to: None,
    };
    let native_terminal = NftCustodyRecordV1 {
        released_to: Some(owner),
        ..native_open.clone()
    };
    let join = JoinGameSessionV1 {
        session_id,
        input_key: key.public_key().clone(),
        application_data: vec![1, 2, 3],
        resources: vec![clause.clone()],
        invitation: None,
        expected_manifest_hash: Hash::new(b"resource-codec-fixture-manifest"),
        expected_asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("equipment", "universal").unwrap(),
            "xor".parse().unwrap(),
        ),
        expected_stake: Quantity::zero(),
    };
    let event = GameSessionEventV1 {
        session_id,
        revision: 3,
        phase: GamePhaseV1::Playing as u8,
        dispute_root: Hash::new(b"resource-codec-fixture-dispute"),
        payout_claims: vec![],
        item_stakes: vec![],
        resources: vec![open.clone()],
        terminal_at_height: None,
    };
    let terminal_event = GameSessionEventV1 {
        revision: 4,
        phase: GamePhaseV1::Cancelled as u8,
        resources: vec![terminal.clone()],
        terminal_at_height: Some(40),
        ..event.clone()
    };
    let mut vectors = Vec::new();
    macro_rules! row {
        ($name:literal, $case:literal, $value:expr, $ty:ty) => {{
            let value: $ty = $value;
            let bare = value.encode();
            assert_eq!(<$ty>::decode(&mut bare.as_slice()).unwrap(), value);
            let framed = norito::to_bytes(&value).unwrap();
            assert_eq!(norito::decode_from_bytes::<$ty>(&framed).unwrap(), value);
            vectors.push(norito::json!({"name":$name,"case":$case,"value":(json::to_value(&value).unwrap()),
                "encoded_hex":(hex::encode_upper(&bare)),"framed_hex":(hex::encode_upper(&framed))}));
        }};
    }
    row!(
        "GameResourceReservationClauseV1",
        "one",
        clause,
        GameResourceReservationClauseV1
    );
    row!(
        "GameResourceRequirementV1",
        "one",
        requirement,
        GameResourceRequirementV1
    );
    row!(
        "GameResourceReservationRecordV1",
        "open",
        open.clone(),
        GameResourceReservationRecordV1
    );
    row!(
        "GameResourceReservationRecordV1",
        "terminal",
        terminal.clone(),
        GameResourceReservationRecordV1
    );
    row!(
        "VecGameResourceReservationRecordV1",
        "open",
        vec![open],
        Vec<GameResourceReservationRecordV1>
    );
    row!(
        "VecGameResourceReservationRecordV1",
        "terminal",
        vec![terminal],
        Vec<GameResourceReservationRecordV1>
    );
    row!(
        "GameResourceReservationSetV1",
        "open",
        open_set,
        GameResourceReservationSetV1
    );
    row!(
        "GameResourceReservationSetV1",
        "terminal",
        terminal_set,
        GameResourceReservationSetV1
    );
    row!(
        "NftCustodyPurposeV1",
        "sale",
        NftCustodyPurposeV1::Sale,
        NftCustodyPurposeV1
    );
    row!(
        "NftCustodyPurposeV1",
        "game_wager",
        NftCustodyPurposeV1::GameWager,
        NftCustodyPurposeV1
    );
    row!(
        "NftCustodyPurposeV1",
        "game_resource",
        purpose,
        NftCustodyPurposeV1
    );
    row!(
        "NftCustodyRecordV1",
        "open",
        native_open,
        NftCustodyRecordV1
    );
    row!(
        "NftCustodyRecordV1",
        "terminal",
        native_terminal,
        NftCustodyRecordV1
    );
    row!(
        "JoinGameSessionV1",
        "nonempty_resources",
        join,
        JoinGameSessionV1
    );
    row!("GameSessionEventV1", "open", event, GameSessionEventV1);
    row!(
        "GameSessionEventV1",
        "terminal",
        terminal_event,
        GameSessionEventV1
    );
    std::fs::write(output, json::to_json_pretty(&norito::json!({"version":1,"network_id":(json::to_value(&network).unwrap()),
        "note":"Actual native canonical wire fixtures; semantic codec examples do not qualify an execution profile or funding.","vectors":vectors})).unwrap()).unwrap();
}
