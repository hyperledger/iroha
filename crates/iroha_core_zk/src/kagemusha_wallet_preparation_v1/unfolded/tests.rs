//! Actual sigma constraint checks using core projections, without lineage proofs.

use ff::Field;
use iroha_kagemusha_proof::admin_sigma::{ArchiveCircuit, LoadCircuit};
use iroha_plonk::check::{CheckMode, check_circuit};

use super::*;

fn fixture() -> (
    KagemushaWalletCredentialV1,
    KagemushaWalletStateV1,
    KagemushaWalletStatementV1,
) {
    let v: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = v["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1")
                && r["variant"].as_str() == Some("Receive")
        })
        .unwrap();
    let capsule: KagemushaWalletRecoveryCapsuleV1 =
        norito::decode_from_bytes(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let original = capsule
        .retained_inputs
        .iter()
        .find(|v| v.role == KagemushaWalletRetainedInputRoleV1::Request)
        .unwrap();
    let request: KagemushaWalletRequestV1 = norito::decode_from_bytes(&original.bytes).unwrap();
    // Only the state and credential are used. The fixture's stand-in proof is
    // deliberately never admitted, and no FoldedState is constructed.
    (
        request.receiver_credential,
        capsule.successor_state,
        capsule.statement,
    )
}

fn statement(
    before: &KagemushaWalletStateV1,
    after: &KagemushaWalletStateV1,
    previous: &KagemushaWalletStatementV1,
    effect: KagemushaWalletEffectV1,
) -> KagemushaWalletStatementV1 {
    KagemushaWalletStatementV1 {
        version: 1,
        scheme_id: before.core.scheme_id,
        relation_id: previous.relation_id,
        credential_digest: after.core.credential_digest,
        asset_digest: before.core.asset_digest,
        lifecycle: after.core.lifecycle,
        sequence: after.core.sequence,
        next_load: after.core.next_load,
        enabled_controls: before.core.enabled_controls,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: before.commitment().unwrap(),
        successor: after.commitment().unwrap(),
        effect,
    }
}

fn project(
    credential: &KagemushaWalletCredentialV1,
    state: &KagemushaWalletStateV1,
    relation: [u8; 32],
) -> StateWitness {
    local_state(credential, state, relation, Fp::from(23).to_repr()).unwrap()
}

#[test]
fn local_projection_preserves_all_fields_and_never_contains_adjusted_evidence() {
    let (credential, state, previous) = fixture();
    let w = project(&credential, &state, previous.relation_id);
    assert_eq!(
        w.core,
        fields::<33>(state.core_field_items().unwrap()).unwrap()
    );
    assert_eq!(
        w.rest,
        fields::<8>(state.rest_field_items().unwrap()).unwrap()
    );
    assert_eq!(w.lineage[5].to_repr(), state.commitment().unwrap().value);
    assert_eq!(w.lineage[14], Fp::from_u128(state.core.burned_total));
    assert_eq!(w.lineage[15].to_repr(), state.core.pending_outgoing_root);
    assert_eq!(
        w.lineage[16].to_repr(),
        KagemushaWalletIndexedTreeV1::new().root()
    );
    let mut wrong = credential;
    wrong.body.wallet_id[0] ^= 1;
    assert!(local_state(&wrong, &state, previous.relation_id, Fp::ONE.to_repr()).is_err());
    let mut wrong = state;
    wrong.core.pending_outgoing_root = [0xff; 32];
    assert!(local_state(&credential, &wrong, previous.relation_id, Fp::ONE.to_repr()).is_err());
    for (relation, key) in [
        ([0; 32], Fp::ONE.to_repr()),
        (previous.relation_id, [0xff; 32]),
    ] {
        assert!(local_state(&credential, &state, relation, key).is_err());
    }
}

#[test]
fn load_sigma_from_core_projection_constrains_value_without_an_omega() {
    let (credential, before, previous) = fixture();
    let mut after = before;
    after.core.sequence += 1;
    after.core.next_load += 1;
    after.core.balance += 7;
    after.core.state_nonce = Fp::from(29).to_repr();
    // The actual insertion is tested by the native-input adapter and owned by
    // A; sigma only carries its new root. This is not a finalized load voucher.
    after.core.load_redeem_recovery_root = Fp::from(31).to_repr();
    let s = statement(
        &before,
        &after,
        &previous,
        KagemushaWalletEffectV1::Load {
            receipt_digest: Fp::from(37).to_repr(),
            load_ordinal: before.core.next_load,
            amount: 7,
            online_charge: 0,
        },
    );
    s.validate_successor_of(&previous).unwrap();
    let witness = LoadWitness {
        predecessor: project(&credential, &before, s.relation_id),
        successor: project(&credential, &after, s.relation_id),
        statement: fields(s.field_items().unwrap()).unwrap(),
    };
    let circuit = LoadCircuit::new(&witness);
    assert!(
        check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let mut wrong = witness;
    wrong.statement[19] += Fp::ONE;
    let circuit = LoadCircuit::new(&wrong);
    assert!(
        !check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let mut wrong = witness;
    wrong.successor.lineage[14] += Fp::ONE;
    let circuit = LoadCircuit::new(&wrong);
    assert!(
        !check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
fn archive_sigma_from_core_projection_preserves_value_and_allows_pending_removal() {
    let (credential, before, previous) = fixture();
    let mut after = before;
    after.core.sequence += 1;
    after.core.state_nonce = Fp::from(41).to_repr();
    after.core.pending_outgoing_root = Fp::from(43).to_repr();
    let effect = KagemushaWalletEffectV1::ArchiveSent {
        credit_id: Fp::from(47).to_repr(),
        credited: Fp::from(53).to_repr(),
    };
    let s = statement(&before, &after, &previous, effect);
    s.validate_successor_of(&previous).unwrap();
    let witness = ArchiveWitness {
        predecessor: project(&credential, &before, s.relation_id),
        successor: project(&credential, &after, s.relation_id),
        statement: fields(s.field_items().unwrap()).unwrap(),
    };
    let circuit = ArchiveCircuit::new(&witness);
    assert!(
        check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    // Rehash the changed state and statement: a consistent content address
    // cannot turn Archive into a refund. Map/evidence validity still belongs to A.
    after.core.balance += 1;
    let s = statement(&before, &after, &previous, effect);
    let wrong = ArchiveWitness {
        predecessor: witness.predecessor,
        successor: project(&credential, &after, s.relation_id),
        statement: fields(s.field_items().unwrap()).unwrap(),
    };
    let circuit = ArchiveCircuit::new(&wrong);
    assert!(
        !check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}
