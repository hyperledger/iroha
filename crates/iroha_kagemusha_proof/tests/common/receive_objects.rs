//! Genuine Receive sigma/state and depth32 maps for an exactly signed Request.
//!
//! The supplied Payment digest is an operation input, not authenticated by this
//! fixture. The full A owner must derive it from the same original byte tapes.

use ff::Field;
use iroha_kagemusha_proof::{
    admin_sigma::{BootstrapWitness, StateWitness},
    operation_relation::map_effects::{CONSUMED_DOMAIN, CREDIT_DOMAIN},
    tree::{BlacklistGap, IndexedInsert, IndexedLeaf, IndexedTree},
    witness::{ReceiveInputs, SigmaRelation, StepInputs, StepWitness},
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};

use super::{bootstrap_objects, send_objects};

#[derive(Clone)]
pub struct ReceiveFixture {
    pub before: StateWitness,
    pub after: StateWitness,
    pub statement: [Fp; 26],
    pub step: StepWitness<Fp>,
    pub consumed: IndexedInsert<Fp>,
    pub credit: IndexedInsert<Fp>,
    pub payment: Fp,
    pub insert: bool,
}

/// Receiver identity of the Request produced by `send_objects::from_load`.
pub fn receiver() -> (
    BootstrapWitness,
    bootstrap_objects::Signed,
    bootstrap_objects::Signed,
) {
    let enrolled = bootstrap_objects::enrollment_for(bootstrap_objects::Identity::Receiver);
    assert_eq!(enrolled.2.bytes, send_objects::receiver_credential().bytes);
    enrolled
}

/// Build the same committed sigma transition for accept or structurally valid
/// burn. The `valid` value is used only to construct a witness; the circuit's
/// terminal predicate must derive its own value from all five result owners.
pub fn from_send(
    send: &send_objects::SendFixture,
    before: &StateWitness,
    payment: Fp,
    valid: bool,
    insert: bool,
) -> ReceiveFixture {
    assert!(!valid || insert);
    let StepInputs::Send(input) = &send.step.inputs else {
        panic!("Send fixture");
    };
    let credit_id = send.statement[17];
    let amount = send.statement[21];
    let sequence = before.core[10] + Fp::ONE;
    let value = hash_with_domain(CONSUMED_DOMAIN, &[credit_id, amount, sequence]);
    let mut consumed_tree = IndexedTree::new();
    assert_eq!(before.core[16], consumed_tree.root());
    let consumed = if insert {
        consumed_tree.insert(credit_id, value).unwrap()
    } else {
        IndexedInsert {
            leaf: IndexedLeaf::sentinel(),
            leaf_slot: 0,
            leaf_siblings: consumed_tree.siblings(0),
            slot: 0,
            slot_siblings: consumed_tree.siblings(0),
        }
    };
    let mut record_tree = IndexedTree::new();
    assert_eq!(before.lineage[16], record_tree.root());
    let record = hash_with_domain(
        CREDIT_DOMAIN,
        &[credit_id, payment, Fp::from(u64::from(!valid))],
    );
    let credit = record_tree.insert(credit_id, record).unwrap();
    let step = StepWitness {
        relation_id: send.step.relation_id,
        predecessor: send_objects::state(before),
        successor_nonce: Fp::from(303),
        inputs: StepInputs::Receive(Box::new(ReceiveInputs {
            payer_wallet: send.step.predecessor.core.identity.wallet_id,
            payer_account_digest: input.payer_account_digest,
            receiver_account_digest: input.receiver_account_digest,
            send_ordinal: send.step.predecessor.core.next_send,
            receiver_credential_digest: input.receiver_credential_digest,
            request: input.request,
            successor_consumed_credit: consumed_tree.root(),
            blacklist: BlacklistGap::unused(),
        })),
    };
    let evaluated = step.evaluate(SigmaRelation::RECEIVE);
    assert!(
        evaluated.violations.is_empty(),
        "{:?}",
        evaluated.violations
    );
    assert_eq!(evaluated.statement[17], credit_id);
    let state = evaluated.successor_state.unwrap();
    let mut after = *before;
    after.core = state.core.fields();
    after.rest = state.rest.fields();
    after.lineage[5] = state.commitment();
    after.lineage[16] = record_tree.root();
    if !valid {
        after.lineage[14] += amount;
    }
    ReceiveFixture {
        before: *before,
        after,
        statement: evaluated.statement,
        step,
        consumed,
        credit,
        payment,
        insert,
    }
}
