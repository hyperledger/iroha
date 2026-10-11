//! Local Load derivation and hostile recovery mutations; no stand-in finality is admitted.

use ff::Field;
use iroha_kagemusha_proof::admin_sigma::LoadCircuit;
use iroha_plonk::check::{CheckMode, check_circuit};

use super::*;

struct Source {
    credential: KagemushaWalletCredentialV1,
    before: KagemushaWalletStateV1,
    receipt: KagemushaWalletLoadReceiptV1,
    insertion: KagemushaWalletIndexedInsertV1,
    after_root: [u8; 32],
    relation: [u8; 32],
}
impl Source {
    fn new() -> Self {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let row = vectors["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1")
                    && row["variant"].as_str() == Some("Receive")
            })
            .unwrap();
        let capsule: KagemushaWalletRecoveryCapsuleV1 = norito::decode_from_bytes(
            &hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let original = retained_original(
            &capsule.retained_inputs,
            KagemushaWalletRetainedInputRoleV1::Request,
        )
        .unwrap();
        let request: KagemushaWalletRequestV1 = norito::decode_from_bytes(original).unwrap();
        let mut before = capsule.successor_state;
        let mut tree = KagemushaWalletIndexedTreeV1::new();
        let other = KagemushaWalletRedeemLeafV1 {
            ordinal: 2,
            nullifier: Fp::from(77).to_repr(),
            amount: 19,
            online_charge: 0,
        };
        tree.insert(other.key(), other.leaf_value().unwrap())
            .unwrap();
        before.core.load_redeem_recovery_root = tree.root();
        let receipt = KagemushaWalletLoadReceiptV1 {
            version: 1,
            scheme_id: before.core.scheme_id,
            asset_digest: before.core.asset_digest,
            wallet_id: before.core.wallet_id,
            request_id: [11; 32],
            ordinal: before.core.next_load,
            amount: 101,
            online_charge: 7,
            charge_quote: Fp::from(37).to_repr(),
            transaction_hash: [13; 32],
            block_height: 2,
            payer_account_digest: [17; 32],
        };
        let leaf = KagemushaWalletLoadLeafV1 {
            ordinal: receipt.ordinal,
            receipt_digest: receipt.receipt_digest().unwrap(),
            amount: receipt.amount,
        };
        let insertion = tree.insert(leaf.key(), leaf.leaf_value().unwrap()).unwrap();
        Self {
            credential: request.receiver_credential,
            before,
            receipt,
            insertion,
            after_root: tree.root(),
            relation: capsule.statement.relation_id,
        }
    }

    fn derive(
        &self,
    ) -> Result<
        (
            KagemushaWalletStateV1,
            KagemushaWalletStatementV1,
            LoadWitness,
        ),
        Error,
    > {
        derive(
            &self.credential,
            &self.before,
            &self.receipt,
            &self.insertion,
            [31; 32],
            self.relation,
            Fp::from(23).to_repr(),
        )
    }
}

#[test]
fn derived_load_matches_strict_sigma_and_only_changes_the_required_fields() {
    let source = Source::new();
    let (state, statement, witness) = source.derive().unwrap();
    assert_eq!(
        state.core.balance,
        source.before.core.balance + source.receipt.amount
    );
    assert_eq!(state.core.next_load, source.before.core.next_load + 1);
    assert_eq!(state.core.sequence, source.before.core.sequence + 1);
    assert_eq!(state.core.load_redeem_recovery_root, source.after_root);
    let mut restored = state.clone();
    restored.core.balance = source.before.core.balance;
    restored.core.next_load = source.before.core.next_load;
    restored.core.sequence = source.before.core.sequence;
    restored.core.state_nonce = source.before.core.state_nonce;
    restored.core.load_redeem_recovery_root = source.before.core.load_redeem_recovery_root;
    assert_eq!(restored, source.before);
    assert_eq!(statement.lineage_burned_total, 0);
    assert_eq!(statement.lineage_pending_outgoing_root, [0; 32]);
    assert_eq!(statement.successor, state.commitment().unwrap());
    let circuit = LoadCircuit::new(&witness);
    assert!(
        check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    // Model data only: this tests exact custody accessors, never the public
    // finality gate or a wallet-open capability.
    let step = LoadStepV1 {
        manifest_digest: [41; 32],
        source_capsule_digest: [43; 32],
        witness,
        state,
        statement,
        retained: [
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadReceipt,
                bytes: source.receipt.to_canonical_bytes().unwrap(),
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadFinality,
                bytes: vec![],
            },
        ],
        openings: [
            source
                .insertion
                .low_opening
                .leaf_transcript(&source.insertion.low),
            source.insertion.slot_opening.empty_transcript(),
        ],
    };
    assert_eq!(step.manifest_digest(), [41; 32]);
    assert_eq!(step.source_capsule_digest(), [43; 32]);
    assert_eq!(
        step.state().commitment().unwrap(),
        step.statement().successor
    );
    assert_eq!(
        step.witness().statement,
        fields::<26>(step.statement().field_items().unwrap()).unwrap()
    );
    let (originals, paths) = step.originals();
    assert_eq!(
        originals[0].bytes,
        source.receipt.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        native_inputs::retained_insertion(paths).unwrap(),
        source.insertion
    );
}

#[test]
fn load_derivation_rejects_replay_foreign_scope_and_wrong_ordinal() {
    for mutation in 0..4 {
        let mut source = Source::new();
        match mutation {
            0 => source.receipt.scheme_id[0] ^= 1,
            1 => source.receipt.asset_digest[0] ^= 1,
            2 => source.receipt.wallet_id[0] ^= 1,
            _ => source.receipt.ordinal += 1,
        }
        assert!(source.derive().is_err(), "mutation{mutation}");
    }
    let mut source = Source::new();
    source.before = source.derive().unwrap().0;
    assert!(source.derive().is_err(), "already absorbed receipt");
}

#[test]
fn load_derivation_authenticates_both_paths_and_checks_every_counter_overflow() {
    for mutation in 0..7 {
        let mut source = Source::new();
        match mutation {
            0 => source.before.core.balance = u128::MAX,
            1 => source.before.core.sequence = u128::MAX,
            2 => {
                source.before.core.next_load = u128::MAX;
                source.receipt.ordinal = u128::MAX;
            }
            3 => source.insertion.slot_opening.slot = source.insertion.low_opening.slot,
            4 => source.insertion.slot_opening.siblings[0] = Fp::ONE.to_repr(),
            5 => source.insertion.low_opening.siblings[0] = Fp::ONE.to_repr(),
            _ => source.insertion.low.next_key = Fp::ONE.to_repr(),
        }
        assert!(source.derive().is_err(), "mutation{mutation}");
    }
}

#[test]
fn every_receipt_term_changes_the_derived_recovery_value_and_committed_state() {
    let original = Source::new().derive().unwrap();
    // An insertion opening authenticates the existing low leaf and empty slot,
    // not the to-be-inserted value. The public full-finality gate authenticates
    // the receipt; this local arithmetic helper must bind every resulting term.
    for mutation in 0..6 {
        let mut source = Source::new();
        match mutation {
            0 => source.receipt.amount += 1,
            1 => source.receipt.online_charge += 1,
            2 => source.receipt.request_id[0] ^= 1,
            3 => source.receipt.transaction_hash[0] ^= 1,
            4 => source.receipt.block_height += 1,
            _ => source.receipt.payer_account_digest[0] ^= 1,
        }
        let (state, statement, witness) = source.derive().unwrap();
        assert_ne!(
            state.core.load_redeem_recovery_root,
            original.0.core.load_redeem_recovery_root
        );
        assert_ne!(statement.successor, original.1.successor);
        assert_ne!(statement.effect, original.1.effect);
        assert_ne!(witness.statement, original.2.statement);
    }
}
