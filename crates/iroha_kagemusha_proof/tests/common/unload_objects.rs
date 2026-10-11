//! Exact loaded-state Unload/Retiring witnesses and original consuming receipts.

use super::{bootstrap, bootstrap_objects, load_objects};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::{BootstrapWitness, ConsumingWitness, StateWitness},
    operation_relation::{
        administrative::NULLIFIER_DOMAIN,
        map_effects::{LOAD_DOMAIN, REDEEM_DOMAIN},
        objects::ObjectKind,
    },
    tree::{IndexedInsert, IndexedTree},
    witness::core_index as core,
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk_gadgets::{bytes::p_bytes_native, statement::STATEMENT_DOMAIN};

pub fn transition(
    before: &StateWitness,
    retiring: bool,
) -> (ConsumingWitness, Option<IndexedInsert<Fp>>) {
    let mut after = BootstrapWitness {
        core: before.core,
        rest: before.rest,
        lineage: before.lineage,
        statement: [Fp::ZERO; 26],
    };
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    after.core[core::BURNED_TOTAL] = before.lineage[14];
    after.core[core::PENDING_OUTGOING_ROOT] = before.lineage[15];
    after.statement[0] = Fp::ONE;
    after.statement[12] = before.lineage[14];
    after.statement[13] = before.lineage[15];
    after.statement[14] = before.lineage[5];
    let insertion = if retiring {
        after.core[core::LIFECYCLE] = Fp::from(2);
        after.statement[16] = Fp::from(8);
        None
    } else {
        let amount = Fp::from(30);
        let ordinal = before.core[core::NEXT_REDEEM];
        let nullifier = hash_with_domain(
            NULLIFIER_DOMAIN,
            &[
                before.core[core::SCHEME],
                before.core[core::SCHEME + 1],
                before.core[core::WALLET],
                before.core[core::WALLET + 1],
                ordinal,
            ],
        );
        after.core[core::BALANCE] -= amount;
        after.core[core::NEXT_REDEEM] += Fp::ONE;
        after.statement[16] = Fp::from(6);
        after.statement[17] = nullifier;
        after.statement[18] = ordinal;
        after.statement[19] = amount;
        // Zero online fees are the default; there is no quote to authenticate.
        let (initial, _, _) = bootstrap_objects::enrollment();
        let (loaded, _, ordinary) = load_objects::funded(&initial);
        let mut tree = IndexedTree::new();
        tree.insert(
            Fp::from(2).pow_vartime([128]),
            hash_with_domain(LOAD_DOMAIN, &[Fp::ZERO, ordinary.digest(), Fp::from(100)]),
        )
        .unwrap();
        assert_eq!(tree.root(), loaded.successor.core[core::LOAD_REDEEM_ROOT]);
        assert_eq!(tree.root(), before.core[core::LOAD_REDEEM_ROOT]);
        let insert = tree
            .insert(
                Fp::from(2).pow_vartime([129]) + ordinal,
                hash_with_domain(REDEEM_DOMAIN, &[ordinal, nullifier, amount, Fp::ZERO]),
            )
            .unwrap();
        after.core[core::LOAD_REDEEM_ROOT] = tree.root();
        Some(insert)
    };
    bootstrap::rebind(&mut after);
    (
        ConsumingWitness {
            predecessor: *before,
            successor: StateWitness::from(&after),
            statement: after.statement,
        },
        insertion,
    )
}

pub fn receipt(w: &ConsumingWitness, omega: &[u8], sigma: &[u8]) -> bootstrap_objects::Signed {
    let mut framed = Vec::new();
    for body in [omega, sigma] {
        framed.extend(u32::try_from(body.len()).unwrap().to_le_bytes());
        framed.extend(body);
    }
    let digest = p_bytes_native(u64::from_le_bytes(*b"kgwprf_1"), &framed);
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            w.predecessor.core[core::WALLET],
            w.predecessor.core[core::WALLET + 1],
            w.statement[16],
            w.statement[17],
        ],
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(bootstrap_objects::id(
        w.predecessor.core[1],
        w.predecessor.core[2],
    ));
    body.extend(bootstrap_objects::id(
        w.predecessor.core[5],
        w.predecessor.core[6],
    ));
    body.extend(bootstrap_objects::small_id(31, 32));
    body.extend(&w.statement[9].to_repr()[..16]);
    for value in [
        operation,
        w.statement[14],
        w.statement[15],
        hash_with_domain(STATEMENT_DOMAIN, &w.statement),
        digest,
    ] {
        body.extend(value.to_repr());
    }
    body.extend(bootstrap_objects::small_id(351, 352));
    body.extend(Fp::ZERO.to_repr());
    bootstrap_objects::sign(ObjectKind::Receipt, body, 29, 71)
}
