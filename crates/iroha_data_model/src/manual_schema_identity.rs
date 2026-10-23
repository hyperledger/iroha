//! Immutable pre-declaration identities and canonical bytes of the three manual model identifier owners.

use crate::{block::BlockHeader, escrow::EscrowId, governance::types::ProposalId, id::NetworkId};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
use norito::{NoritoDeserialize, NoritoSerialize, codec::Encode, json::Value};

trait FixtureValue:
    Clone
    + norito::NoritoSchema
    + NoritoSerialize
    + for<'de> NoritoDeserialize<'de>
    + norito::json::JsonSerialize
    + norito::json::JsonDeserialize
{
}

impl<T> FixtureValue for T where
    T: Clone
        + norito::NoritoSchema
        + NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + norito::json::JsonSerialize
        + norito::json::JsonDeserialize
{
}

fn record<T: FixtureValue>(case: &str, value: &T) -> Value {
    assert_eq!(T::frame_name(), T::nominal_name());
    let bare = value.encode();
    let frame = norito::encode_canonical(value).expect("encode complete manual identity frame");
    let decoded: T =
        norito::decode_canonical(&frame).expect("decode complete manual identity frame");
    assert_eq!(decoded.encode(), bare);
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
    let header = norito::core::Header::read(std::io::Cursor::new(&frame)).unwrap();
    assert_eq!(header.schema, norito::schema::identity::frame_hash::<T>());
    let mut wrong_schema = frame.clone();
    wrong_schema[6] ^= 1;
    assert!(norito::decode_canonical::<T>(&wrong_schema).is_err());
    assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());

    let json = {
        let text = norito::json::to_json(value).expect("encode manual identity JSON");
        let decoded: T = norito::json::from_json(&text).expect("decode manual identity JSON");
        assert_eq!(decoded.encode(), bare);
        assert_eq!(norito::json::to_json(&decoded).unwrap(), text);
        Value::from(text)
    };
    norito::json!({
        "case": case,
        "declared_nominal_name": (T::nominal_name()),
        "serialize_hash": (hex::encode(norito::schema::identity::frame_hash::<T>())),
        "deserialize_hash": (hex::encode(norito::schema::identity::frame_hash::<T>())),
        "header_flags": (header.flags),
        "bare_hex": (hex::encode(bare)),
        "frame_hex": (hex::encode(frame)),
        "json": json,
    })
}

fn family<T: FixtureValue>(rows: &mut Vec<Value>, label: &str, value: T, signer: &KeyPair) {
    let hash = HashOf::new(&value);
    let signature = SignatureOf::try_from_hash(signer.private_key(), hash)
        .expect("sign public deterministic fixture value");
    signature
        .verify(signer.public_key(), &value)
        .expect("verify fixture signature");
    signature
        .verify_hash(signer.public_key(), hash)
        .expect("verify exact fixture hash");
    rows.extend([
        record(&format!("{label}/root"), &value),
        record(&format!("{label}/option-none"), &None::<T>),
        record(&format!("{label}/option-some"), &Some(value.clone())),
        record(&format!("{label}/vec-empty"), &Vec::<T>::new()),
        record(&format!("{label}/vec-two"), &vec![value.clone(), value]),
        record(&format!("{label}/hash-of"), &hash),
        record(&format!("{label}/signature-of"), &signature),
    ]);
}

fn current_frames() -> Value {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    // Public test-only key material, matching the existing identity fixture workflow.
    let signer = KeyPair::try_from_seed(
        b"Iroha crypto wire identity fixtures only".to_vec(),
        Algorithm::Ed25519,
    )
    .expect("deterministic public fixture signer");
    let mut rows = Vec::new();

    // Exact existing id::tests::network_id_fixture construction; the hash is already marked.
    let genesis_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA5; Hash::LENGTH]));
    let network = NetworkId::from_genesis_hash(genesis_hash);
    assert_eq!(network.encode(), genesis_hash.encode());
    assert_eq!(network.encode(), vec![0xA5; Hash::LENGTH]);

    assert_eq!(
        norito::json::to_json(&network).unwrap(),
        norito::json::to_json(&genesis_hash).unwrap(),
    );
    family(&mut rows, "network-id", network, &signer);

    // Exact existing escrow::tests::asset_escrow_record_roundtrips_norito value.
    let escrow_hash = Hash::new("escrow-roundtrip");
    let escrow = EscrowId::new(escrow_hash);
    assert_eq!(escrow.encode(), escrow_hash.encode());

    assert_eq!(
        norito::json::to_json(&escrow).unwrap(),
        norito::json::to_json(&escrow_hash).unwrap(),
    );
    family(&mut rows, "escrow-id", escrow, &signer);

    // Exact existing parliament_types::tests::proposal_id_json_roundtrip value.
    // Its binary owner uses versioned HashWire32, not the raw Hash payload above.
    let proposal = ProposalId([0xAB; 32]);

    assert_eq!(
        norito::json::to_json(&proposal).unwrap(),
        format!("\"{}\"", "ab".repeat(32)),
    );
    family(&mut rows, "proposal-id", proposal, &signer);

    assert_eq!(rows.len(), 21);
    let cases: std::collections::BTreeSet<_> = rows
        .iter()
        .map(|row| row.get("case").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(cases.len(), rows.len(), "every capture case is unique");
    norito::json!({
        "schema": 1,
        "governance_enabled": true,
        "json_enabled": true,
        "records": rows,
    })
}

#[test]
fn manual_model_identity_frames_match_pre_declaration_goldens() {
    let mut frozen: Value = norito::json::from_str(include_str!(
        "../tests/fixtures/manual-model-governance-true-json-true.json"
    ))
    .expect("immutable observed model fixtures");
    let mut current = current_frames();
    let captured_rows = frozen.get_mut("records").unwrap().as_array_mut().unwrap();
    let declared_rows = current.get_mut("records").unwrap().as_array_mut().unwrap();
    assert_eq!(declared_rows.len(), captured_rows.len());
    for (declared, captured) in declared_rows.iter_mut().zip(captured_rows.iter_mut()) {
        assert_eq!(declared.get("case"), captured.get("case"));
        // Physical moves may change Rust's type_name, but never the captured wire identity.
        assert_eq!(
            declared.get("declared_nominal_name"),
            captured.get("actual_type_name"),
        );
        declared
            .as_object_mut()
            .unwrap()
            .remove("declared_nominal_name");
        captured.as_object_mut().unwrap().remove("actual_type_name");
    }
    assert_eq!(current, frozen);
}
