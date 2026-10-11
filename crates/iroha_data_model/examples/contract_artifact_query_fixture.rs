//! Emit deterministic, native contract-artifact query vectors for SDK consumers.

use std::{
    collections::BTreeMap,
    fmt::{Debug, Write as _},
    num::NonZeroU64,
};

use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey};
use iroha_data_model::{
    NetworkId,
    account::{AccountId, address::ChainDiscriminantGuard},
    query::{
        QueryRequest, SignedQuery, SingularQueryBox,
        smart_contract::FindContractManifestByArtifactId,
    },
    smart_contract::ContractArtifactId,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_version::codec::EncodeVersioned as _;
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize, json, json::Value};

// fixture_version 1 binds bare request/payload bytes to the fixed Norito v1
// COMPACT_LEN layout (0x02): compact per-value lengths; sequence length and
// collection offset framing are unchanged. Consumers must read this metadata,
// never infer layout from payload bytes or enable retired packed-layout bits.
const FIXTURE_LAYOUT_FLAGS: u8 = 0x02;
const PROOF_RECORD_BACKEND: &str = "pipa-r/pasta";

const NETWORK: &str = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
// Public disposable SDK fixture seed, never a wallet or deployment credential.
const SEED: &[u8; 32] = b"android-fixture-signing-key-0102";

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("write into String");
    }
    output
}

// Match the permanent generated_queries capture's root/Vec/Option/map checks.
// These are native frames, including schema headers; no canonical hash is synthesized.
fn checked_frame<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + Debug + PartialEq,
{
    let bytes = norito::to_bytes(value).expect("encode artifact query frame");
    let decoded: T = norito::decode_from_bytes(&bytes).expect("decode artifact query frame");
    assert_eq!(&decoded, value);
    let header = norito::core::Header::read(bytes.as_slice()).expect("read frame header");
    assert_eq!(header.schema, norito::schema::identity::frame_hash::<T>());
    let mut wrong_schema = bytes.clone();
    wrong_schema[6] ^= 1;
    assert!(matches!(
        norito::decode_from_bytes::<T>(&wrong_schema),
        Err(norito::Error::SchemaMismatch)
    ));
    hex(&bytes)
}

fn identity_frame_capture() -> Value {
    let query = FindContractManifestByArtifactId::new(ContractArtifactId::new(
        DataSpaceId::new(u64::MAX),
        Hash::new(b"query contract"),
    ));
    let value = norito::json::to_value(&query).expect("artifact query JSON");
    let decoded: FindContractManifestByArtifactId =
        norito::json::from_value(value.clone()).expect("decode artifact query JSON");
    assert_eq!(decoded, query);
    let identity_hash = norito::schema::identity::frame_hash::<FindContractManifestByArtifactId>();
    assert_eq!(
        FindContractManifestByArtifactId::frame_name(),
        FindContractManifestByArtifactId::nominal_name()
    );
    json!({
        "nominal": (FindContractManifestByArtifactId::nominal_name()),
        "serialize_hash": (hex(&identity_hash)),
        "deserialize_hash": (hex(&identity_hash)),
        "cases": [{
            "json": value,
            "frame": (checked_frame(&query)),
            "vector_frame": (checked_frame(&vec![query.clone()])),
            "option_frame": (checked_frame(&Some(query.clone()))),
            "map_frame": (checked_frame(&BTreeMap::from([(7_u8, query)]))),
        }],
    })
}

fn signed_query_case(
    name: &str,
    query: SingularQueryBox,
    inputs: &Value,
    network: NetworkId,
    authority: &AccountId,
    keypair: &KeyPair,
    nonce: [u8; 32],
) -> Value {
    let request = QueryRequest::Singular(query);
    let request_bytes = norito::codec::encode_adaptive(&request);
    let payload = request.with_authority(
        network,
        authority.clone(),
        1_000_000,
        NonZeroU64::new(10_000).expect("nonzero fixture TTL"),
        nonce,
    );
    let payload_bytes = norito::codec::encode_adaptive(&payload);
    let signed = payload.try_sign(keypair).expect("sign native query case");
    signed
        .verify_signature()
        .expect("verify native case signature");
    let framed = norito::to_bytes(&signed).expect("frame native case");
    let decoded: SignedQuery = norito::decode_from_bytes(&framed).expect("native case roundtrip");
    decoded
        .verify_signature()
        .expect("verify decoded native case");
    assert_eq!(decoded.encode_versioned(), signed.encode_versioned());
    json!({
        "name": name,
        "inputs": inputs,
        "query_request_hex": (hex(&request_bytes)),
        "payload_hex": (hex(&payload_bytes)),
        "signed_query_versioned_hex": (hex(&signed.encode_versioned())),
    })
}

// One typed native case for every singular query implemented by the managed SDK.
// Binary newtypes and enum tags come from their actual Encode implementations.
fn managed_singular_cases(
    network: NetworkId,
    authority: &AccountId,
    keypair: &KeyPair,
    nonce: [u8; 32],
) -> Vec<Value> {
    use iroha_data_model::{
        asset::AssetBalanceScope,
        da::types::StorageTicketId,
        oracle::KeyedHash,
        prelude::{AssetDefinitionId, AssetId},
        proof::ProofId,
        query,
        sorafs::{capacity::ProviderId, pin_registry::ManifestDigest},
    };
    use iroha_model_base::{domain::DomainId, topology::LaneId};
    let domain = DomainId::try_new("banka", "universal").expect("fixture domain");
    let definition = AssetDefinitionId::derive_from_components(
        domain.clone(),
        "coin".parse().expect("fixture asset name"),
    );
    let artifact_id = ContractArtifactId::new(
        DataSpaceId::new(u64::MAX),
        Hash::new(b"contract-artifact-query-sdk-v1"),
    );
    let digest = Hash::new(b"public native query digest");
    let queries: [(&str, SingularQueryBox, Value); 18] = [
        (
            "FindExecutorDataModel",
            query::executor::FindExecutorDataModel.into(),
            json!({}),
        ),
        (
            "FindParameters",
            query::executor::FindParameters.into(),
            json!({}),
        ),
        (
            "FindAliasesByAccountId",
            query::account::FindAliasesByAccountId::new(
                authority.clone(),
                Some("paynet".to_owned()),
                Some("banka".to_owned()),
            )
            .into(),
            json!({"account_id": (authority.to_string()), "dataspace": "paynet", "domain": "banka"}),
        ),
        (
            "FindProofRecordById",
            query::proof::FindProofRecordById::new(ProofId {
                backend: PROOF_RECORD_BACKEND.to_owned(),
                proof_hash: [0x27; 32],
            })
            .into(),
            json!({"backend": PROOF_RECORD_BACKEND, "proof_hash": (hex(&[0x27; 32]))}),
        ),
        (
            "FindContractManifestByArtifactId",
            query::smart_contract::FindContractManifestByArtifactId::new(artifact_id).into(),
            json!({"artifact_id": artifact_id}),
        ),
        (
            "FindAbiVersion",
            query::runtime::FindAbiVersion.into(),
            json!({}),
        ),
        (
            "FindAssetById",
            query::asset::FindAssetById::new(AssetId::with_scope(
                definition.clone(),
                authority.clone(),
                AssetBalanceScope::Dataspace(DataSpaceId::new(9)),
            ))
            .into(),
            json!({"asset_definition_id": (definition.to_string()), "account_id": (authority.to_string()), "dataspace_id": 9}),
        ),
        (
            "FindAssetDefinitionById",
            query::asset::FindAssetDefinitionById::new(definition.clone()).into(),
            json!({"asset_definition_id": (definition.to_string())}),
        ),
        (
            "FindTwitterBindingByHash",
            query::oracle::FindTwitterBindingByHash::new(KeyedHash {
                pepper_id: "pepper-v1".to_owned(),
                digest,
            })
            .into(),
            json!({"pepper_id": "pepper-v1", "digest_hex": (hex(digest.as_ref()))}),
        ),
        (
            "FindDomainEndorsements",
            query::endorsement::FindDomainEndorsements::new(domain.clone()).into(),
            json!({"domain_id": (domain.to_string())}),
        ),
        (
            "FindDomainEndorsementPolicy",
            query::endorsement::FindDomainEndorsementPolicy::new(domain.clone()).into(),
            json!({"domain_id": (domain.to_string())}),
        ),
        (
            "FindDomainCommittee",
            query::endorsement::FindDomainCommittee::new("committee-7".to_owned()).into(),
            json!({"committee_id": "committee-7"}),
        ),
        (
            "FindDaPinIntentByTicket",
            query::da::FindDaPinIntentByTicket::new(StorageTicketId::new([0x28; 32])).into(),
            json!({"storage_ticket": (hex(&[0x28; 32]))}),
        ),
        (
            "FindDaPinIntentByManifest",
            query::da::FindDaPinIntentByManifest::new(ManifestDigest::new([0x29; 32])).into(),
            json!({"manifest_digest": (hex(&[0x29; 32]))}),
        ),
        (
            "FindDaPinIntentByAlias",
            query::da::FindDaPinIntentByAlias::new("manifest-root".to_owned()).into(),
            json!({"alias": "manifest-root"}),
        ),
        (
            "FindDaPinIntentByLaneEpochSequence",
            query::da::FindDaPinIntentByLaneEpochSequence::new(LaneId::new(7), 11, 13).into(),
            json!({"lane_id": 7, "epoch": 11, "sequence": 13}),
        ),
        (
            "FindSorafsProviderOwner",
            query::sorafs::FindSorafsProviderOwner::new(ProviderId([0x2a; 32])).into(),
            json!({"provider_id": (hex(&[0x2a; 32]))}),
        ),
        (
            "FindDataspaceNameOwnerById",
            query::sns::FindDataspaceNameOwnerById::new(DataSpaceId::new(42)).into(),
            json!({"dataspace_id": 42}),
        ),
    ];
    queries
        .into_iter()
        .map(|(name, query, inputs)| {
            signed_query_case(name, query, &inputs, network, authority, keypair, nonce)
        })
        .collect()
}

fn fixture() -> Value {
    assert_eq!(norito::core::default_encode_flags(), FIXTURE_LAYOUT_FLAGS);
    let _address_scope = ChainDiscriminantGuard::enter(753);
    let keypair = KeyPair::from_private_key(
        PrivateKey::from_bytes(Algorithm::Ed25519, SEED).expect("public fixture private key"),
    )
    .expect("public fixture keypair");
    let authority = AccountId::new(keypair.public_key().clone());
    let network: NetworkId = NETWORK.parse().expect("canonical fixture network");
    let code_hash = Hash::new(b"contract-artifact-query-sdk-v1");
    let nonce = [0x5a; 32];
    let mut cases = Vec::new();
    for dataspace in [0, u64::MAX] {
        let artifact_id = ContractArtifactId::new(DataSpaceId::new(dataspace), code_hash);
        let request = QueryRequest::Singular(SingularQueryBox::FindContractManifestByArtifactId(
            FindContractManifestByArtifactId::new(artifact_id),
        ));
        let request_bytes = norito::codec::encode_adaptive(&request);
        let payload = request.with_authority(
            network,
            authority.clone(),
            1_000_000,
            NonZeroU64::new(10_000).expect("nonzero fixture TTL"),
            nonce,
        );
        let payload_bytes = norito::codec::encode_adaptive(&payload);
        let signed = payload.try_sign(&keypair).expect("sign fixture query");
        signed
            .verify_signature()
            .expect("verify signed native query");
        let framed = norito::to_bytes(&signed).expect("frame native signed query");
        let decoded: SignedQuery =
            norito::decode_from_bytes(&framed).expect("verify native query roundtrip");
        decoded
            .verify_signature()
            .expect("verify decoded native query");
        assert_eq!(decoded.encode_versioned(), signed.encode_versioned());
        cases.push(json!({
            "artifact_id": artifact_id,
            "query_request_hex": (hex(&request_bytes)),
            "payload_hex": (hex(&payload_bytes)),
            "signed_query_versioned_hex": (hex(&signed.encode_versioned())),
        }));
    }
    json!({
        "fixture_version": 1,
        "norito_layout_version": 1,
        "norito_layout_flags": FIXTURE_LAYOUT_FLAGS,
        "generator": "iroha_data_model/examples/contract_artifact_query_fixture.rs",
        "network_id": network,
        "authority": (authority.to_string()),
        "test_seed_hex": (hex(SEED)),
        "creation_time_ms": 1_000_000_u64,
        "time_to_live_ms": 10_000_u64,
        "nonce_hex": (hex(&nonce)),
        "cases": cases,
        "identity_frame_capture": (identity_frame_capture()),
        "singular_cases": (managed_singular_cases(network, &authority, &keypair, nonce)),
    })
}

fn main() {
    println!(
        "{}",
        norito::json::to_json_pretty(&fixture()).expect("render native fixture")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_record_fixture_binds_the_current_registry_backend_in_native_bytes() {
        let fixture = fixture();
        let case = fixture
            .get("singular_cases")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case.get("name").unwrap().as_str() == Some("FindProofRecordById"))
            .unwrap();
        assert_eq!(
            case.get("inputs").unwrap().get("backend").unwrap().as_str(),
            Some("pipa-r/pasta")
        );
        let expected = QueryRequest::Singular(
            iroha_data_model::query::proof::FindProofRecordById::new(
                iroha_data_model::proof::ProofId {
                    backend: "pipa-r/pasta".to_owned(),
                    proof_hash: [0x27; 32],
                },
            )
            .into(),
        );
        let (bytes, flags) = norito::codec::encode_with_header_flags(&expected);
        assert_eq!(flags, FIXTURE_LAYOUT_FLAGS);
        assert_eq!(
            case.get("query_request_hex").unwrap().as_str(),
            Some(hex(&bytes).as_str())
        );
    }

    #[test]
    fn every_managed_singular_query_has_an_authenticated_native_case() {
        let fixture = fixture();
        let cases = fixture.get("singular_cases").unwrap().as_array().unwrap();
        assert_eq!(cases.len(), 18);
        let names: std::collections::BTreeSet<_> = cases
            .iter()
            .map(|case| case.get("name").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 18);
        for case in cases {
            assert!(
                !case
                    .get("query_request_hex")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !case
                    .get("payload_hex")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !case
                    .get("signed_query_versioned_hex")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn identity_capture_keeps_all_four_native_frame_contexts() {
        let row = identity_frame_capture();
        let cases = row.get("cases").unwrap().as_array().unwrap();
        assert_eq!(cases.len(), 1);
        let case = &cases[0];
        for key in ["frame", "vector_frame", "option_frame", "map_frame"] {
            assert!(
                case.get(key)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .starts_with("4e525430")
            );
        }
        assert_eq!(
            case.get("json")
                .unwrap()
                .get("artifact_id")
                .unwrap()
                .get("dataspace_id")
                .unwrap()
                .as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(row.get("serialize_hash"), row.get("deserialize_hash"));
    }

    #[test]
    fn native_query_fixture_is_deterministic_and_binds_both_dataspaces() {
        let first = fixture();
        assert_eq!(first, fixture());
        assert_eq!(
            FIXTURE_LAYOUT_FLAGS,
            norito::core::header_flags::COMPACT_LEN
        );
        assert_eq!(
            first.get("norito_layout_version").unwrap().as_u64(),
            Some(1)
        );
        assert_eq!(first.get("norito_layout_flags").unwrap().as_u64(), Some(2));
        let cases = first.get("cases").unwrap().as_array().unwrap();
        assert_eq!(cases.len(), 2);
        assert_ne!(cases[0].get("payload_hex"), cases[1].get("payload_hex"));
        assert_ne!(
            cases[0].get("signed_query_versioned_hex"),
            cases[1].get("signed_query_versioned_hex")
        );
    }
}
