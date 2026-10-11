//! Ordinary receipt terms, state/map and own signed receipt witnesses for Load.
//! Synthetic ledger terms exercise components only; they carry no finality authority.

use super::bootstrap_objects::{Signed, id, key, sign, small_id};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::own::OwnPolicy,
    admin_sigma::{BootstrapWitness, LoadWitness, StateWitness},
    operation_relation::{map_effects::LOAD_DOMAIN, objects::ObjectKind},
    tree::{IndexedInsert, IndexedTree},
    witness::core_index as core,
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk_gadgets::{bytes::p_bytes_native, statement::STATEMENT_DOMAIN};

#[derive(Clone)]
pub struct OrdinaryReceipt {
    pub bytes: [u8; 282],
}
impl OrdinaryReceipt {
    pub fn digest(&self) -> Fp {
        p_bytes_native(u64::from_le_bytes(*b"kgwolod1"), &self.bytes)
    }
}
pub fn funded(before: &BootstrapWitness) -> (LoadWitness, IndexedInsert<Fp>, OrdinaryReceipt) {
    let mut body = 1u16.to_le_bytes().to_vec();
    for offset in [1, 3, 5] {
        body.extend(id(before.core[offset], before.core[offset + 1]));
    }
    body.extend(small_id(103, 104));
    body.extend(before.core[core::NEXT_LOAD].to_repr()[..16].iter());
    body.extend(100u128.to_le_bytes());
    body.extend(3u128.to_le_bytes());
    body.extend(Fp::from(104).to_repr());
    body.extend(small_id(105, 106));
    body.extend(107u64.to_le_bytes());
    body.extend(small_id(108, 109));
    let ordinary = OrdinaryReceipt {
        bytes: body.try_into().unwrap(),
    };
    let mut after = *before;
    after.core[core::BALANCE] += Fp::from(100);
    after.core[core::NEXT_LOAD] += Fp::ONE;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    let ordinal = before.core[core::NEXT_LOAD];
    let key = Fp::from(2).pow_vartime([128]) + ordinal;
    let value = hash_with_domain(LOAD_DOMAIN, &[ordinal, ordinary.digest(), Fp::from(100)]);
    let mut tree = IndexedTree::new();
    assert_eq!(tree.root(), before.core[core::LOAD_REDEEM_ROOT]);
    let insertion = tree.insert(key, value).unwrap();
    after.core[core::LOAD_REDEEM_ROOT] = tree.root();
    super::bootstrap::rebind(&mut after);
    let mut statement = after.statement;
    statement[14] = before.lineage[5];
    statement[16] = Fp::from(2);
    statement[17..].fill(Fp::ZERO);
    statement[17] = ordinary.digest();
    statement[18] = ordinal;
    statement[19] = Fp::from(100);
    statement[20] = Fp::from(3);
    (
        LoadWitness {
            predecessor: StateWitness::from(before),
            successor: StateWitness::from(&after),
            statement,
        },
        insertion,
        ordinary,
    )
}
pub fn receipt(w: &LoadWitness, sigma: &[u8]) -> Signed {
    let mut tape = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
    tape.extend_from_slice(sigma);
    let digest = p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &tape);
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            w.successor.core[5],
            w.successor.core[6],
            Fp::from(2),
            w.statement[17],
        ],
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(id(w.successor.core[1], w.successor.core[2]));
    body.extend(id(w.successor.core[5], w.successor.core[6]));
    body.extend(small_id(31, 32));
    body.extend_from_slice(&w.statement[9].to_repr()[..16]);
    for value in [
        operation,
        w.statement[14],
        w.statement[15],
        hash_with_domain(STATEMENT_DOMAIN, &w.statement),
        digest,
    ] {
        body.extend(value.to_repr());
    }
    body.extend(small_id(101, 102));
    body.extend(Fp::ZERO.to_repr());
    sign(ObjectKind::Receipt, body, 29, 53)
}
pub fn policy() -> OwnPolicy {
    OwnPolicy::new([31, 32], key(23)).unwrap()
}

/// Separate mandatory C4 signature leaf: current credential and fixed-root certificate.
pub fn current_signatures(
    witnesses: &[iroha_kagemusha_proof::q_signature::SignatureWitness; 2],
) -> (
    iroha_kagemusha_proof::q_signature::QSignatureCircuit,
    [Vec<iroha_pasta::Fq>; 1],
) {
    use iroha_kagemusha_proof::q_signature::{
        QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureSlot,
    };
    use iroha_plonk_gadgets::p256::VerifyMode;
    let plan = QSignaturePlan::new(vec![
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Variable,
        },
        SignatureSlot {
            mode: VerifyMode::Hard,
            key: SignatureKey::Fixed(key(23)),
        },
    ])
    .unwrap();
    let circuit = QSignatureCircuit::new(plan, witnesses.to_vec()).unwrap();
    let instances = circuit.instances(&[true; 2]).unwrap();
    (circuit, instances)
}

/// Own Advance receipt signature, independent of ledger consensus finality.
pub fn own_signature(
    witness: iroha_kagemusha_proof::q_signature::SignatureWitness,
) -> (
    iroha_kagemusha_proof::q_signature::QSignatureCircuit,
    [Vec<iroha_pasta::Fq>; 1],
) {
    use iroha_kagemusha_proof::q_signature::{
        QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureSlot,
    };
    let plan = QSignaturePlan::new(vec![SignatureSlot {
        mode: iroha_plonk_gadgets::p256::VerifyMode::Hard,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let circuit = QSignatureCircuit::new(plan, vec![witness]).unwrap();
    let instances = circuit.instances(&[true]).unwrap();
    (circuit, instances)
}
