//! Genuine Request bytes and native Send transition after an authenticated Load.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::StateWitness,
    controls::QuotaWitness,
    operation_relation::{
        map_effects::{FEE_DOMAIN, PENDING_DOMAIN},
        objects::ObjectKind,
    },
    tree::{BlacklistGap, IndexedInsert, IndexedLeaf, IndexedTree},
    witness::{
        Controls, CoreState, Identity, LineageInputs, MapRoots, RequestBody, RequestTerms,
        SendInputs, SigmaRelation, StateRest, StateV1, StepInputs, StepWitness,
    },
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};

use super::bootstrap_objects::{Signed, enrollment, id, key, sec1, sign, small_id};

#[derive(Clone)]
pub struct SendFixture {
    pub before: StateWitness,
    pub after: StateWitness,
    pub statement: [Fp; 26],
    pub step: StepWitness<Fp>,
    pub pending: IndexedInsert<Fp>,
    pub fee: IndexedInsert<Fp>,
    pub objects: [Vec<u8>; 3],
}
fn integer(value: Fp) -> u128 {
    let repr = value.to_repr();
    assert_eq!(&repr[16..], &[0; 16]);
    u128::from_le_bytes(repr[..16].try_into().unwrap())
}
fn pair(words: &[Fp]) -> [u8; 32] {
    id(words[0], words[1]).try_into().unwrap()
}
fn narrow(value: Fp) -> u64 {
    integer(value).try_into().unwrap()
}
pub fn state(w: &StateWitness) -> StateV1<Fp> {
    let c = &w.core;
    let r = &w.rest;
    StateV1 {
        core: CoreState {
            lifecycle: narrow(c[0]).try_into().unwrap(),
            identity: Identity {
                scheme_id: pair(&c[1..3]),
                asset_digest: pair(&c[3..5]),
                wallet_id: pair(&c[5..7]),
                credential_digest: c[7].to_repr(),
            },
            balance: integer(c[8]),
            burned_total: integer(c[9]),
            sequence: integer(c[10]),
            next_send: integer(c[11]),
            next_load: integer(c[12]),
            next_redeem: integer(c[13]),
            send_chain: c[14],
            recv_chain: c[15],
            roots: MapRoots {
                consumed_credit: c[16],
                pending_outgoing: c[17],
                load_redeem_recovery: c[18],
                fee_claim_recovery: c[19],
                quota_usage: c[20],
            },
            controls: Controls {
                enabled: narrow(c[21]).try_into().unwrap(),
                quota_windows_root: c[22],
                quota_share_expires_at_ms: narrow(c[23]),
                blacklist_version: narrow(c[24]),
                blacklist_root: c[25],
                blacklist_issued_at_ms: narrow(c[26]),
                blacklist_max_age_ms: narrow(c[27]),
                time_anchor_max_response_ms: narrow(c[28]),
                lease_expires_at_ms: narrow(c[29]),
            },
            policy_epoch: narrow(c[30]),
            accepted_time_floor_ms: narrow(c[31]),
            state_nonce: c[32],
        },
        rest: StateRest {
            permitted_controls: narrow(r[0]).try_into().unwrap(),
            scheme_policy: r[1].to_repr(),
            fee_schedule: r[2].to_repr(),
            blacklist: r[3].to_repr(),
            quota_share: r[4].to_repr(),
            quota_share_id: narrow(r[5]),
            time_anchor: r[6].to_repr(),
            blacklist_history_root: r[7].to_repr(),
        },
    }
}
pub fn receiver_credential() -> Signed {
    let (_, _, original) = enrollment();
    let mut body = original.bytes[..ObjectKind::Credential.body_len()].to_vec();
    body[66..98].copy_from_slice(&small_id(71, 72));
    body[98..130].copy_from_slice(&small_id(73, 74));
    body[130..195].copy_from_slice(&sec1(key(43)));
    sign(ObjectKind::Credential, body, 17, 53)
}
fn request(body: &RequestBody) -> Signed {
    let mut bytes = 1u16.to_le_bytes().to_vec();
    for id in [
        body.scheme_id,
        body.asset_digest,
        body.payer_wallet,
        body.payer_account,
        body.receiver_wallet,
        body.receiver_account,
    ] {
        bytes.extend(id);
    }
    bytes.extend(body.send_ordinal.to_le_bytes());
    bytes.extend(body.receiver_credential_digest);
    bytes.extend(body.terms.amount.to_le_bytes());
    bytes.extend(body.terms.fee_schedule);
    bytes.extend(body.terms.fee.to_le_bytes());
    bytes.extend(body.terms.policy_epoch.to_le_bytes());
    bytes.extend(body.terms.scheme_policy);
    bytes.extend(body.terms.request_time.to_le_bytes());
    bytes.extend(body.terms.receiver_blacklist_version.to_le_bytes());
    bytes.extend(body.terms.receiver_blacklist_root);
    bytes.extend(body.terms.certificates);
    bytes.extend(body.terms.nonce);
    sign(ObjectKind::Request, bytes, 43, 59)
}
pub fn from_load(before: &StateWitness) -> SendFixture {
    build(before, None, &receiver_credential())
}
/// Exact quoted receiver credential used by renewed Receive source fixtures.
#[allow(dead_code)] // Used only by renewed Receive consumers of this shared fixture.
pub fn from_load_with_receiver_credential(before: &StateWitness, receiver: &Signed) -> SendFixture {
    build(before, None, receiver)
}
/// Component-only prior installed fee policy; recursive use must prove its installation.
pub fn with_held_fee(before: &StateWitness) -> SendFixture {
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(id(before.core[1], before.core[2]));
    body.extend(id(before.core[3], before.core[4]));
    body.extend(1u64.to_le_bytes());
    body.extend(small_id(91, 92));
    body.extend(0u32.to_le_bytes());
    body.extend(3u128.to_le_bytes());
    body.extend(0u128.to_le_bytes());
    body.extend(1000u128.to_le_bytes());
    body.push(1);
    body.extend(Fp::from(93).to_repr());
    let schedule = sign(ObjectKind::FeeSchedule, body, 19, 61);
    let mut installed = *before;
    installed.rest[1] = Fp::from(94);
    installed.rest[2] = schedule.digest();
    installed.core[30] = Fp::ONE;
    installed.lineage[13] += Fp::from(256);
    installed.lineage[5] = state(&installed).commitment();
    build(&installed, Some(&schedule), &receiver_credential())
}
fn build(before: &StateWitness, schedule: Option<&Signed>, receiver: &Signed) -> SendFixture {
    let predecessor = state(before);
    assert_eq!(predecessor.core.fields(), before.core);
    assert_eq!(predecessor.rest.fields::<Fp>(), before.rest);
    let (_, _, payer) = enrollment();
    assert_eq!(payer.digest(), before.core[7]);
    let terms = RequestTerms {
        amount: 12,
        fee: if schedule.is_some() { 3 } else { 0 },
        fee_schedule: schedule.map_or(Fp::ZERO, Signed::digest).to_repr(),
        policy_epoch: 0,
        scheme_policy: [0; 32],
        request_time: 0,
        receiver_blacklist_version: 0,
        receiver_blacklist_root: [0; 32],
        certificates: Fp::from(83).to_repr(),
        nonce: small_id(84, 85).try_into().unwrap(),
    };
    let body = RequestBody {
        scheme_id: predecessor.core.identity.scheme_id,
        asset_digest: predecessor.core.identity.asset_digest,
        payer_wallet: predecessor.core.identity.wallet_id,
        payer_account: small_id(9, 10).try_into().unwrap(),
        receiver_wallet: small_id(71, 72).try_into().unwrap(),
        receiver_account: small_id(73, 74).try_into().unwrap(),
        send_ordinal: predecessor.core.next_send,
        receiver_credential_digest: receiver.digest().to_repr(),
        terms,
    };
    let request = request(&body);
    let credit = body.credit_id::<Fp>();
    let receiver = [Fp::from(71), Fp::from(72)];
    let descriptor = hash_with_domain(
        PENDING_DOMAIN,
        &[
            credit,
            receiver[0],
            receiver[1],
            Fp::from_u128(body.send_ordinal),
            Fp::from(12),
            Fp::from_u128(terms.fee),
            request.digest(),
        ],
    );
    let mut pending_tree = IndexedTree::<Fp>::new();
    assert_eq!(pending_tree.root(), before.lineage[15]);
    let pending = pending_tree.insert(credit, descriptor).unwrap();
    let mut fee_tree = IndexedTree::<Fp>::new();
    assert_eq!(fee_tree.root(), before.core[19]);
    let fee = if let Some(schedule) = schedule {
        let value = hash_with_domain(
            FEE_DOMAIN,
            &[credit, Fp::from_u128(terms.fee), schedule.digest()],
        );
        fee_tree.insert(credit, value).unwrap()
    } else {
        IndexedInsert {
            leaf: IndexedLeaf::sentinel(),
            leaf_slot: 0,
            leaf_siblings: fee_tree.siblings(0),
            slot: 0,
            slot_siblings: fee_tree.siblings(0),
        }
    };
    let step = StepWitness {
        relation_id: pair(&before.lineage[3..5]),
        predecessor,
        successor_nonce: Fp::from(202),
        inputs: StepInputs::Send(Box::new(SendInputs {
            payer_account_digest: body.payer_account,
            receiver_wallet: body.receiver_wallet,
            receiver_account_digest: body.receiver_account,
            receiver_credential_digest: body.receiver_credential_digest,
            request: terms,
            request_digest: request.digest().to_repr(),
            accepted_lower: 1,
            accepted_upper: 1,
            lineage: LineageInputs {
                burned_total: integer(before.lineage[14]),
                pending_outgoing_root: before.lineage[15],
            },
            successor_pending_outgoing: pending_tree.root(),
            successor_fee_claim: fee_tree.root(),
            blacklist: BlacklistGap::unused(),
            quota: Box::new(QuotaWitness::unused()),
        })),
    };
    let evaluation = step.evaluate(SigmaRelation::SEND);
    assert!(
        evaluation.violations.is_empty(),
        "{:?}",
        evaluation.violations
    );
    let state = evaluation.successor_state.unwrap();
    let mut after = *before;
    after.core = state.core.fields();
    after.rest = state.rest.fields();
    after.lineage[5] = state.commitment();
    after.lineage[14] = after.core[9];
    after.lineage[15] = pending_tree.root();
    SendFixture {
        before: *before,
        after,
        statement: evaluation.statement,
        step,
        pending,
        fee,
        objects: [
            payer.bytes,
            request.bytes,
            schedule.map_or_else(
                || vec![0; ObjectKind::FeeSchedule.body_len() + 64],
                |s| s.bytes.clone(),
            ),
        ],
    }
}
