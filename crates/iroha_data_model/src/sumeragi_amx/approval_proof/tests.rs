//! Genuine native signatures over synthetic permission preimages; native execution is tested in Core.

use super::*;
use crate::{
    IntoKeyValue, Registrable,
    account::Account,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetId},
    block::consensus::SumeragiRootScope,
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, test_fixtures::NativeFinalityFixture,
        world_state_value_hash_v1,
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::topology::DataSpaceId;

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
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
fn rebuild(proof: &mut AmxDebitApprovalProofV1, approval: &AmxDebitApprovalV1) {
    let owner = approval.debited_asset.account();
    let relay = account(92);
    let mut entries = Vec::new();
    for id in [owner, &relay] {
        let (_, value) = Account::new(id.clone()).build(owner).into_key_value();
        entries.push(row("world.accounts", id, &value));
    }
    let definition = AssetDefinition::numeric(
        approval.debited_asset.definition().clone(),
        "AMX approval asset",
        AssetBalancePolicy::DataspaceRestricted,
        None,
    )
    .build(owner);
    entries.push(row(
        "world.asset_definitions",
        approval.debited_asset.definition(),
        &definition,
    ));
    entries.push(row(
        "world.account_permissions",
        &relay,
        &proof.relay_permissions,
    ));
    entries
        .sort_by(|a, b| (&a.field_id, a.kind, a.key_hash).cmp(&(&b.field_id, b.kind, b.key_hash)));
    proof.world.entries = entries;
}
fn certify(
    native: &mut NativeFinalityFixture,
    proof: &AmxDebitApprovalProofV1,
) -> VerifiedSumeragiBlock {
    let block = native.block_with_submitted_work(native.next_header());
    let certificate = native.certify_with_world_root(block, proof.world.root().unwrap());
    native
        .verifier()
        .verify_retained_decision(&certificate)
        .unwrap()
}
fn fixture() -> (
    NativeFinalityFixture,
    AmxDebitApprovalV1,
    AmxDebitApprovalProofV1,
    VerifiedSumeragiBlock,
) {
    let parent = NativeFinalityFixture::new().network_id();
    let dataspace = DataSpaceId::new((1_u64 << 40) + 23);
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: parent,
        dataspace_id: dataspace,
    };
    let mut native = NativeFinalityFixture::start_with_scope("debit-approval-private", scope);
    let approval = AmxDebitApprovalV1 {
        global_network: parent,
        participant_network: native.network_id(),
        participant_instance: native.verifier().instance().0,
        dataspace,
        transaction_id: [71; 32],
        debited_asset: AssetId::with_scope(
            "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
            account(91),
            AssetBalanceScope::Dataspace(dataspace),
        ),
    };
    let mut proof = AmxDebitApprovalProofV1 {
        world: WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"qualified AMX approval schema specimen"),
            entries: Vec::new(),
        },
        relay_permissions: Permissions::from([approval.permission().unwrap()]),
    };
    rebuild(&mut proof, &approval);
    let block = certify(&mut native, &proof);
    (native, approval, proof, block)
}

#[test]
fn exact_debit_approval_authenticates_and_borrowed_frame_preserves_canonical_layout() {
    let (native, approval, proof, block) = fixture();
    let verified = proof
        .verify(&approval, &account(92), proof.world.schema_hash, &block)
        .unwrap();
    assert_eq!(verified.approval(), &approval);
    assert_eq!(verified.relay(), &account(92));
    assert_eq!(verified.height(), block.height());
    assert_eq!(verified.context_id(), block.context_id());
    assert_eq!(
        block.native_instance_id(),
        Some(native.verifier().instance().0)
    );
    let bytes = norito::encode_canonical(&proof).unwrap();
    let borrowed = AmxDebitApprovalProofRefV1::new(&proof.world, &proof.relay_permissions);
    assert_eq!(norito::encode_canonical(&borrowed).unwrap(), bytes);
    assert_eq!(
        norito::json::to_vec(&borrowed).unwrap(),
        norito::json::to_vec(&proof).unwrap()
    );
    assert_eq!(
        AmxDebitApprovalProofV1::decode_frame(&bytes).unwrap(),
        proof
    );
    assert_eq!(
        norito::json::from_slice::<AmxDebitApprovalProofV1>(&norito::json::to_vec(&proof).unwrap())
            .unwrap(),
        proof
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AmxDebitApprovalProofV1::decode_frame(&trailing).is_err());
    assert!(AmxDebitApprovalProofV1::decode_frame(&[]).is_err());
    let genesis = native
        .verifier()
        .verify_retained_decision(native.genesis_proof())
        .unwrap();
    assert_eq!(genesis.native_instance_id(), None);
    assert!(
        proof
            .verify(&approval, &account(92), proof.world.schema_hash, &genesis)
            .is_err()
    );
}

#[test]
fn exact_debit_approval_rejects_substituted_roots_terms_relays_schema_and_permission_preimages() {
    let (_, approval, proof, block) = fixture();
    let reject = |selected: &AmxDebitApprovalV1| {
        assert!(
            proof
                .verify(selected, &account(92), proof.world.schema_hash, &block)
                .is_err()
        );
    };
    let mut changed = approval.clone();
    changed.transaction_id[0] ^= 1;
    reject(&changed);
    changed = approval.clone();
    changed.participant_instance[0] ^= 1;
    reject(&changed);
    changed = approval.clone();
    changed.participant_network = approval.global_network;
    reject(&changed);
    changed = approval.clone();
    changed.global_network = approval.participant_network;
    reject(&changed);
    changed = approval.clone();
    changed.dataspace = DataSpaceId::new(24);
    reject(&changed);
    changed = approval.clone();
    changed.debited_asset = AssetId::with_scope(
        approval.debited_asset.definition().clone(),
        account(93),
        *approval.debited_asset.scope(),
    );
    reject(&changed);
    assert!(
        proof
            .verify(&approval, &account(93), proof.world.schema_hash, &block)
            .is_err()
    );
    assert!(
        proof
            .verify(
                &approval,
                &account(92),
                Hash::new(b"foreign schema"),
                &block
            )
            .is_err()
    );
    let mut forged = proof.clone();
    forged.relay_permissions.clear();
    assert!(
        forged
            .verify(&approval, &account(92), proof.world.schema_hash, &block)
            .is_err()
    );
    forged
        .relay_permissions
        .insert(approval.permission().unwrap());
    forged
        .world
        .entries
        .retain(|entry| entry.field_id != "world.account_permissions");
    assert!(
        forged
            .verify(&approval, &account(92), proof.world.schema_hash, &block)
            .is_err()
    );
    let mut global = NativeFinalityFixture::new();
    let foreign = certify(&mut global, &proof);
    assert!(
        proof
            .verify(&approval, &account(92), proof.world.schema_hash, &foreign)
            .is_err()
    );
}

#[test]
fn exact_debit_approval_is_historical_and_cannot_override_a_later_revocation() {
    let (mut native, approval, old, old_block) = fixture();
    let mut revoked = old.clone();
    revoked.relay_permissions.clear();
    rebuild(&mut revoked, &approval);
    let revoked_block = certify(&mut native, &revoked);
    assert!(
        old.verify(&approval, &account(92), old.world.schema_hash, &old_block)
            .is_ok()
    );
    assert!(
        old.verify(
            &approval,
            &account(92),
            old.world.schema_hash,
            &revoked_block
        )
        .is_err()
    );
    assert!(
        revoked
            .verify(
                &approval,
                &account(92),
                old.world.schema_hash,
                &revoked_block
            )
            .is_err()
    );
    // Even a genuinely certified row containing a permission for different terms cannot
    // satisfy the independently selected exact approval.
    let mut changed = approval.clone();
    changed.transaction_id[0] ^= 1;
    revoked
        .relay_permissions
        .insert(changed.permission().unwrap());
    rebuild(&mut revoked, &approval);
    let changed_block = certify(&mut native, &revoked);
    assert!(
        revoked
            .verify(
                &approval,
                &account(92),
                old.world.schema_hash,
                &changed_block
            )
            .is_err()
    );
}
