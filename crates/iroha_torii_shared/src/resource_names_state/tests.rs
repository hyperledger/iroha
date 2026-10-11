//! Genuine native signatures over explicitly synthetic World fixture data.
use super::*;
use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    Registrable,
    account::AccountId,
    asset::{AssetBalancePolicy, AssetDefinitionId},
    sumeragi::{SumeragiFootprint, SumeragiStatus},
    sumeragi_finality::{
        SumeragiFinalityAttestationBody, WorldStateElementKindV1, WorldStateSnapshotEntryV1,
        test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
    },
};
use iroha_model_base::peer::PeerId;
use norito::codec::Encode as _;
use std::sync::OnceLock;

fn fixture() -> &'static NativeResourceNamesStateV1 {
    static FIXTURE: OnceLock<NativeResourceNamesStateV1> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let asset: AssetDefinitionId = "839FV3NJC8NfgWQvghXU2hEFQm9a".parse().unwrap();
        let owner = AccountId::new(
            KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let definition = iroha_data_model::asset::AssetDefinition::numeric(
            asset.clone(),
            "Synthetic fixture",
            AssetBalancePolicy::Global,
            None,
        )
        .build(&owner);
        let incarnation = iroha_data_model::nexus::AxtAssetIncarnationV1::try_from_bytes(
            *Hash::new(b"fixture registration").as_ref(),
        )
        .unwrap();
        let watermark = 7_u64;
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"synthetic complete World registry"),
            entries: vec![
                WorldStateSnapshotEntryV1 {
                    field_id: "world.asset_definitions".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
                    value_hash: world_state_value_hash_v1(&definition).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.axt_asset_incarnations".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&asset).unwrap()),
                    value_hash: world_state_value_hash_v1(&incarnation).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.soracloud_sequence_watermark".into(),
                    kind: WorldStateElementKindV1::Cell,
                    key_hash: None,
                    value_hash: world_state_value_hash_v1(&watermark).unwrap(),
                },
            ],
        };
        let mut native = NativeFinalityFixture::start("shared authority state fixture");
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let node = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
        let node_id = PeerId::new(node.public_key().clone());
        let config = Hash::new(b"fixture native configuration");
        let body = SumeragiFinalityAttestationBody {
            observed_at_unix_ms: 1_000_000,
            challenge: [7; 32],
            network_id: native.network_id(),
            node_fingerprint: Hash::new(node_id.encode()),
            node_id,
            build_fingerprint: Hash::new(b"fixture native binary"),
            config_fingerprint: config,
            genesis_block_hash: native.genesis().hash(),
            genesis_finality_proof: native.genesis_proof().clone(),
            status: SumeragiStatus {
                protocol_version: 1,
                config_fingerprint: config,
                beacon_horizon: None,
                instance: native.verifier().instance().0,
                height: 3,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: 2,
                applied_height: 2,
                awaiting: false,
                signer: Some(node.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: SumeragiFootprint::default(),
            },
            finality_proof: proof,
        };
        let attestation = SumeragiFinalityAttestation {
            signature: SignatureOf::try_from_hash(node.private_key(), body.signing_hash()).unwrap(),
            body,
        };
        attestation.verify().unwrap();
        let verified_tip = native
            .verifier()
            .verify_retained_decision(native.latest())
            .unwrap();
        snapshot.authenticate(&verified_tip).unwrap();
        NativeResourceNamesStateV1 {
            attestation,
            world_snapshot: snapshot,
            asset_alias_bindings: vec![
                NativeAssetAliasBindingOriginalV1 {
                    definition_id: asset.clone(),
                    binding_record_wire: vec![1, 2, 3, 4],
                },
                NativeAssetAliasBindingOriginalV1 {
                    definition_id: AssetDefinitionId::derive_from_components(
                        iroha_model_base::domain::DomainId::parse_fully_qualified(
                            "fixture.universal",
                        )
                        .unwrap(),
                        "other".parse().unwrap(),
                    ),
                    binding_record_wire: vec![8, 9],
                },
            ],
            smart_contract_keys: vec![
                "sns/records/4099/is2".parse().unwrap(),
                "sns/records/4099/is3".parse().unwrap(),
                "private/customer-name".parse().unwrap(),
            ],
            dataspace_names: vec![
                NativeDataspaceSnsOriginalV1 {
                    storage_key: "sns/records/4099/is2".parse().unwrap(),
                    raw_value: vec![5, 6, 7],
                },
                NativeDataspaceSnsOriginalV1 {
                    storage_key: "sns/records/4099/is3".parse().unwrap(),
                    raw_value: vec![],
                },
            ],
        }
    })
}

#[test]
fn complete_names_borrowed_wire_and_bounded_json_are_exact_owned_layout() {
    let value = fixture();
    let aliases: Vec<_> = value
        .asset_alias_bindings
        .iter()
        .map(|row| {
            NativeAssetAliasBindingOriginalRefV1::new(&row.definition_id, &row.binding_record_wire)
        })
        .collect();
    let keys: Vec<_> = value.smart_contract_keys.iter().collect();
    let names: Vec<_> = value
        .dataspace_names
        .iter()
        .map(|row| NativeDataspaceSnsOriginalRefV1::new(&row.storage_key, &row.raw_value))
        .collect();
    let borrowed = NativeResourceNamesStateRefV1::new(
        &value.attestation,
        &value.world_snapshot,
        &aliases,
        &keys,
        &names,
    );
    let bytes = norito::encode_canonical(value).unwrap();
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), bytes);
    assert_eq!(
        decode_unverified_native_resource_names_state_v1(&bytes).unwrap(),
        *value
    );
    assert_eq!(
        norito::json::to_json_bounded(&borrowed, 2 * 1024 * 1024).unwrap(),
        norito::json::to_json_bounded(value, 2 * 1024 * 1024).unwrap()
    );
    let json = norito::json::to_json_bounded(&borrowed, 2 * 1024 * 1024).unwrap();
    let decoded: NativeResourceNamesStateV1 = norito::json::from_slice(json.as_bytes()).unwrap();
    assert_eq!(decoded, *value);
}

#[test]
fn complete_names_carrier_refuses_noncanonical_trailing_and_oversized_inputs() {
    let mut bytes = norito::encode_canonical(fixture()).unwrap();
    bytes.push(0);
    assert!(decode_unverified_native_resource_names_state_v1(&bytes).is_err());
    assert!(decode_unverified_native_resource_names_state_v1(&[]).is_err());
    let bytes = vec![0u8; NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1 + 1];
    assert!(decode_unverified_native_resource_names_state_v1(&bytes).is_err());
}

#[test]
fn s17_temporary_print_shape_fixture() {
    let value = fixture();
    println!(
        "S17ATTESTATION {}",
        norito::json::to_json(&value.attestation).unwrap()
    );
    println!(
        "S17SNAPSHOT {}",
        norito::json::to_json(&value.world_snapshot).unwrap()
    );
}
