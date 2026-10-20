//! Genuine native finality signatures over synthetic public pool preimages; no prover authority.

use super::*;
use crate::sumeragi_finality::{
    WorldStateElementKindV1, WorldStateSnapshotEntryV1, test_fixtures::NativeFinalityFixture,
    world_state_value_hash_v1,
};
use iroha_model_base::topology::{DataSpaceId, LaneId};

fn row<K: norito::codec::Encode, V: norito::codec::Encode>(
    field: &str,
    key: &K,
    value: &V,
) -> WorldStateSnapshotEntryV1 {
    WorldStateSnapshotEntryV1 {
        field_id: field.into(),
        kind: WorldStateElementKindV1::Table,
        key_hash: Some(world_state_value_hash_v1(key).unwrap()),
        value_hash: world_state_value_hash_v1(value).unwrap(),
    }
}
pub fn fixture() -> (PrivateSettlementPoolKeyV1, PrivateSettlementPoolCutProofV1) {
    let key = PrivateSettlementPoolKeyV1 {
        route: PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(17),
            lane_id: LaneId::new(3),
            lane_incarnation: Hash::new(b"selected lane incarnation"),
        },
        pool_id: PrivacyPoolIdV1::new([19; 32]),
    };
    let governance = PrivateSettlementPoolGovernanceProjectionV1 {
        version: 1,
        route: key.route,
        pool_id: key.pool_id,
        asset_binding_commitment: Hash::new(b"opaque asset mapping"),
        audit_policy_digest: Hash::new(b"audit policy"),
        audit_key_epoch: 1,
        lifecycle: PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: 1,
            activation_height: 1,
            retirement_height: None,
        },
        governance_digest: Hash::new(b"restricted governance"),
        prior_revisions: Vec::new(),
    };
    let pool = PrivateSettlementPoolStateV1 {
        version: 1,
        route: key.route,
        pool_id: key.pool_id,
        restricted_pool_policy_digest: governance.governance_digest,
        epoch: 1,
        root: PrivacyRootV1::new([21; 32]),
        tree_size: 1,
        leaf: Some([23; 32]),
        ommers: Vec::new(),
    };
    let mut entries = vec![
        row("world.private_settlement_governance", &key, &governance),
        row("world.private_settlement_pools", &key, &pool),
    ];
    entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
    (
        key,
        PrivateSettlementPoolCutProofV1 {
            world: WorldStateSnapshotV1 {
                schema_hash: Hash::new(b"independently selected native schema fixture"),
                entries,
            },
            governance,
            pool,
        },
    )
}
fn certify(
    native: &mut NativeFinalityFixture,
    proof: &PrivateSettlementPoolCutProofV1,
) -> VerifiedSumeragiBlock {
    let block = native.block_with_submitted_work(native.next_header());
    let certificate = native.certify_with_world_root(block, proof.world.root().unwrap());
    native
        .verifier()
        .verify_retained_decision(&certificate)
        .unwrap()
}

#[test]
fn private_pool_cut_binds_exact_rows_and_borrowed_canonical_frame() {
    let (key, proof) = fixture();
    let mut native = NativeFinalityFixture::new();
    let block = certify(&mut native, &proof);
    let cut = proof
        .verify(native.network_id(), proof.world.schema_hash, key, &block)
        .unwrap();
    assert_eq!(cut.key(), key);
    assert_eq!(cut.context_id(), block.context_id());
    assert_eq!(cut.height(), block.height());
    assert_eq!(cut.pool(), &proof.pool);
    assert_eq!(cut.governance(), &proof.governance);
    cut.verify_nullifier_absent(PrivacyNullifierV1::new([33; 32]))
        .unwrap();
    cut.verify_output_absent(PrivacyCommitmentV1::new([34; 32]))
        .unwrap();
    let encoded = norito::encode_canonical(&proof).unwrap();
    let borrowed =
        PrivateSettlementPoolCutProofRefV1::new(&proof.world, &proof.governance, &proof.pool);
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), encoded);
    assert_eq!(
        norito::json::to_vec(&borrowed).unwrap(),
        norito::json::to_vec(&proof).unwrap()
    );
    assert_eq!(
        PrivateSettlementPoolCutProofV1::decode_frame(&encoded).unwrap(),
        proof
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert!(PrivateSettlementPoolCutProofV1::decode_frame(&trailing).is_err());
    assert!(PrivateSettlementPoolCutProofV1::decode_frame(&[]).is_err());
}

#[test]
fn private_pool_cut_rejects_network_schema_key_value_and_genesis_substitution() {
    let (key, proof) = fixture();
    let mut native = NativeFinalityFixture::new();
    let block = certify(&mut native, &proof);
    let network = native.network_id();
    let schema = proof.world.schema_hash;
    let foreign = NativeFinalityFixture::start("different-private-context-network").network_id();
    assert_ne!(foreign, network);
    assert!(proof.verify(foreign, schema, key, &block).is_err());
    assert!(
        proof
            .verify(network, Hash::new(b"foreign schema"), key, &block)
            .is_err()
    );
    let mut changed_key = key;
    changed_key.pool_id = PrivacyPoolIdV1::new([35; 32]);
    assert!(proof.verify(network, schema, changed_key, &block).is_err());
    let mut changed = proof.clone();
    changed.pool.epoch += 1;
    assert!(changed.verify(network, schema, key, &block).is_err());
    let mut changed = proof.clone();
    changed.governance.audit_key_epoch += 1;
    assert!(changed.verify(network, schema, key, &block).is_err());
    let mut incomplete = proof.clone();
    incomplete.world.entries.pop();
    assert!(incomplete.verify(network, schema, key, &block).is_err());
    let genesis = native
        .verifier()
        .verify_retained_decision(native.genesis_proof())
        .unwrap();
    assert!(proof.verify(network, schema, key, &genesis).is_err());
}

#[test]
fn private_pool_cut_absence_is_exact_and_cannot_ignore_existing_typed_keys() {
    let (key, mut proof) = fixture();
    let nullifier = PrivacyNullifierV1::new([36; 32]);
    let commitment = PrivacyCommitmentV1::new([37; 32]);
    proof.world.entries.extend([
        row(
            "world.private_settlement_nullifiers",
            &PrivateSettlementNullifierKeyV1 {
                pool: key,
                nullifier,
            },
            &Hash::new(b"original spent reference"),
        ),
        row(
            "world.private_settlement_outputs",
            &PrivateSettlementOutputKeyV1 {
                pool: key,
                commitment,
            },
            &Hash::new(b"original output reference"),
        ),
    ]);
    proof
        .world
        .entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
    let mut native = NativeFinalityFixture::new();
    let block = certify(&mut native, &proof);
    let cut = proof
        .verify(native.network_id(), proof.world.schema_hash, key, &block)
        .unwrap();
    assert!(cut.verify_nullifier_absent(nullifier).is_err());
    assert!(cut.verify_output_absent(commitment).is_err());
    cut.verify_nullifier_absent(PrivacyNullifierV1::new([38; 32]))
        .unwrap();
    cut.verify_output_absent(PrivacyCommitmentV1::new([39; 32]))
        .unwrap();
}

#[test]
fn private_pool_cut_refuses_an_independently_authenticated_private_root() {
    let (key, proof) = fixture();
    let global = NativeFinalityFixture::new();
    let mut private = NativeFinalityFixture::start_with_scope(
        "private-context-participant-root",
        SumeragiRootScope::Dataspace {
            parent_network_id: global.network_id(),
            dataspace_id: key.route.dataspace_id,
        },
    );
    let block = certify(&mut private, &proof);
    assert_ne!(block.root_scope(), SumeragiRootScope::Global);
    assert!(
        proof
            .verify(private.network_id(), proof.world.schema_hash, key, &block)
            .is_err()
    );
}

#[test]
fn private_pool_public_keys_roundtrip_once_with_exact_canonical_json_spelling() {
    use norito::json::JsonKeyCodec;
    fn check<T>(value: &T)
    where
        T: norito::NoritoSerialize
            + for<'a> norito::NoritoDeserialize<'a>
            + JsonKeyCodec
            + PartialEq
            + std::fmt::Debug,
    {
        let mut json = String::new();
        value.encode_json_key(&mut json);
        let literal: String = norito::json::from_str(&json).unwrap();
        assert_eq!(T::decode_json_key(&literal).unwrap(), *value);
        assert_eq!(literal, hex::encode_upper(norito::to_bytes(value).unwrap()));
        assert!(T::decode_json_key(&literal.to_ascii_lowercase()).is_err());
        assert!(T::decode_json_key(&format!("{literal}00")).is_err());
    }
    let (key, _) = fixture();
    check(&key);
    check(&PrivateSettlementNullifierKeyV1 {
        pool: key,
        nullifier: PrivacyNullifierV1::new([41; 32]),
    });
    check(&PrivateSettlementOutputKeyV1 {
        pool: key,
        commitment: PrivacyCommitmentV1::new([42; 32]),
    });
}
