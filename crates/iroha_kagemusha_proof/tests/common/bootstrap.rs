//! Deterministic initial-state witness, shared by sigma and recursive tests.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::BootstrapWitness,
    tree::{IndexedTree, QuotaUsageTree, QuotaWindowTree},
    witness::{CORE_DOMAIN, REST_DOMAIN, core_index as core},
};
use iroha_pasta::{Fp, poseidon::hash_with_domain};

pub fn witness() -> BootstrapWitness {
    let mut w = BootstrapWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ONE; 18],
        statement: [Fp::ZERO; 26],
    };
    w.core[core::LIFECYCLE] = Fp::ONE;
    for (i, value) in w.core.iter_mut().enumerate().take(8).skip(1) {
        *value = Fp::from(u64::try_from(i).unwrap());
    }
    let empty = IndexedTree::<Fp>::new().root();
    w.core[core::CONSUMED_CREDIT_ROOT..=core::FEE_CLAIM_ROOT].fill(empty);
    w.core[core::QUOTA_USAGE_ROOT] =
        QuotaUsageTree::<Fp>::new(&QuotaWindowTree::new(&[]).unwrap()).root();
    w.core[core::STATE_NONCE] = Fp::from(77);
    w.rest[7] = empty;
    w.lineage[3] = Fp::from(9);
    w.lineage[4] = Fp::from(10);
    w.lineage[14] = Fp::ZERO;
    w.lineage[15] = empty;
    w.lineage[16] = empty;
    w.lineage[17] = Fp::from(91);
    w.statement[0] = Fp::ONE;
    w.statement[16] = Fp::ONE;
    w.statement[17..21].copy_from_slice(&[Fp::ONE, Fp::from(2), Fp::from(3), Fp::from(4)]);
    rebind(&mut w);
    w
}

pub fn rebind(w: &mut BootstrapWitness) {
    let mut preimage = w.core.to_vec();
    preimage.push(hash_with_domain(REST_DOMAIN, &w.rest));
    w.lineage[5] = hash_with_domain(CORE_DOMAIN, &preimage);
    w.lineage[1..3].copy_from_slice(&w.core[core::SCHEME..=core::SCHEME + 1]);
    w.lineage[6..8].copy_from_slice(&w.core[core::WALLET..core::WALLET + 2]);
    w.lineage[8] = w.core[core::CREDENTIAL];
    w.lineage[13] = w.core[core::LIFECYCLE]
        + Fp::from(256) * w.core[core::POLICY_EPOCH]
        + Fp::from_u128(1 << 72) * w.core[core::ENABLED_CONTROLS];
    w.statement[1..3].copy_from_slice(&w.lineage[3..5]);
    w.statement[3..7].copy_from_slice(&w.core[core::SCHEME..core::ASSET + 2]);
    w.statement[7] = w.core[core::CREDENTIAL];
    w.statement[8] = w.core[core::LIFECYCLE];
    w.statement[9] = w.core[core::SEQUENCE];
    w.statement[10] = w.core[core::NEXT_LOAD];
    w.statement[15] = w.lineage[5];
}
