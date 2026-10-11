//! Genuine Unload/Retiring leaves and rehashed hostile state transitions.

#[path = "common/bootstrap.rs"]
mod bootstrap;
mod common;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    admin_sigma::{
        ArchiveCircuit, ArchiveWitness, ConsumingWitness, RetiringCircuit, StateWitness,
        UnloadCircuit,
    },
    operation_relation::administrative::NULLIFIER_DOMAIN,
    witness::{CORE_DOMAIN, REST_DOMAIN, core_index as core},
};
use iroha_pasta::{Fp, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_claim,
    frontend::{Circuit, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::statement::STATEMENT_DOMAIN;

const K: u32 = 12;

fn rebind(w: &mut ConsumingWitness) {
    for state in [&mut w.predecessor, &mut w.successor] {
        let mut preimage = state.core.to_vec();
        preimage.push(hash_with_domain(REST_DOMAIN, &state.rest));
        state.lineage[5] = hash_with_domain(CORE_DOMAIN, &preimage);
        state.lineage[1..3].copy_from_slice(&state.core[core::SCHEME..=core::SCHEME + 1]);
        state.lineage[6..8].copy_from_slice(&state.core[core::WALLET..core::WALLET + 2]);
        state.lineage[8] = state.core[core::CREDENTIAL];
        state.lineage[13] = state.core[core::LIFECYCLE]
            + Fp::from(256) * state.core[core::POLICY_EPOCH]
            + Fp::from_u128(1 << 72) * state.core[core::ENABLED_CONTROLS];
    }
    w.statement[3..7].copy_from_slice(&w.successor.core[core::SCHEME..core::ASSET + 2]);
    for (field, index) in [
        (7, core::CREDENTIAL),
        (8, core::LIFECYCLE),
        (9, core::SEQUENCE),
        (10, core::NEXT_LOAD),
    ] {
        w.statement[field] = w.successor.core[index];
    }
    w.statement[12] = w.predecessor.lineage[14];
    w.statement[13] = w.predecessor.lineage[15];
    w.statement[14] = w.predecessor.lineage[5];
    w.statement[15] = w.successor.lineage[5];
}

fn witness(retiring: bool) -> ConsumingWitness {
    let initial = bootstrap::witness();
    let mut predecessor = StateWitness::from(&initial);
    predecessor.core[core::BALANCE] = Fp::from(100);
    predecessor.core[core::BURNED_TOTAL] = Fp::from(2);
    // Folding may increase burned value and change the pending root without
    // rewriting the previous core. The consuming step must synchronize both.
    predecessor.lineage[14] = Fp::from(10);
    predecessor.lineage[15] = Fp::from(101);
    let mut successor = predecessor;
    successor.core[core::SEQUENCE] += Fp::ONE;
    successor.core[core::STATE_NONCE] += Fp::ONE;
    successor.core[core::BURNED_TOTAL] = predecessor.lineage[14];
    successor.core[core::PENDING_OUTGOING_ROOT] = predecessor.lineage[15];
    let mut statement = initial.statement;
    statement[17..].fill(Fp::ZERO);
    if retiring {
        successor.core[core::LIFECYCLE] = Fp::from(2);
        statement[16] = Fp::from(8);
    } else {
        successor.core[core::BALANCE] = Fp::from(70);
        successor.core[core::NEXT_REDEEM] = Fp::ONE;
        // A must prove this recovery root's exact insertion.
        successor.core[core::LOAD_REDEEM_ROOT] = Fp::from(99);
        statement[16] = Fp::from(6);
        statement[17] = hash_with_domain(
            NULLIFIER_DOMAIN,
            &[
                predecessor.core[core::SCHEME],
                predecessor.core[core::SCHEME + 1],
                predecessor.core[core::WALLET],
                predecessor.core[core::WALLET + 1],
                predecessor.core[core::NEXT_REDEEM],
            ],
        );
        statement[19] = Fp::from(30);
        statement[20] = Fp::from(3);
        statement[21] = Fp::from(43);
    }
    let mut w = ConsumingWitness {
        predecessor,
        successor,
        statement,
    };
    rebind(&mut w);
    w
}

fn instances(w: &ConsumingWitness) -> [Vec<Fp>; 1] {
    [vec![hash_with_domain(STATEMENT_DOMAIN, &w.statement)]]
}

fn accepts(w: &ConsumingWitness, retiring: bool) -> bool {
    let public = instances(w);
    let result = if retiring {
        check_circuit(&RetiringCircuit::new(w), K, &public, CheckMode::Strict)
    } else {
        check_circuit(&UnloadCircuit::new(w), K, &public, CheckMode::Strict)
    };
    result.is_ok_and(|report| report.is_satisfied())
}

fn shape<C: Circuit<Fp>>(circuit: &C, public: &[Vec<Fp>]) {
    let known = synthesize(circuit, K, Some(public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), K, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let rows: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |row| row + 1))
        .collect();
    assert_eq!(rows.len(), 5);
    eprintln!("{} k{K}: rows={rows:?}", std::any::type_name::<C>());
}

#[test]
fn consuming_leaves_bind_every_unchanged_field_and_adjusted_value() {
    for retiring in [false, true] {
        let honest = witness(retiring);
        assert!(accepts(&honest, retiring), "honest retiring={retiring}");
        if retiring {
            shape(&RetiringCircuit::new(&honest), &instances(&honest));
        } else {
            shape(&UnloadCircuit::new(&honest), &instances(&honest));
        }
        for index in 0..33 {
            if index == core::STATE_NONCE || (!retiring && index == core::LOAD_REDEEM_ROOT) {
                continue;
            }
            let mut wrong = honest;
            wrong.successor.core[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(
                !accepts(&wrong, retiring),
                "retiring={retiring}, rehashed core {index}"
            );
        }
        for index in 0..8 {
            let mut wrong = honest;
            wrong.successor.rest[index] += Fp::ONE;
            rebind(&mut wrong);
            assert!(
                !accepts(&wrong, retiring),
                "retiring={retiring}, rehashed rest {index}"
            );
        }
        for index in [14, 15, 16, 17] {
            let mut wrong = honest;
            wrong.successor.lineage[index] += Fp::ONE;
            assert!(
                !accepts(&wrong, retiring),
                "retiring={retiring}, lineage {index}"
            );
        }
        let mut wrong = honest;
        wrong.successor.core[core::STATE_NONCE] = Fp::ZERO;
        rebind(&mut wrong);
        assert!(!accepts(&wrong, retiring));
    }
}

#[test]
fn unload_rejects_burned_spend_bad_nullifier_charge_and_counter_wrap() {
    let honest = witness(false);
    let mut all_available = honest;
    all_available.statement[19] = Fp::from(90);
    all_available.successor.core[core::BALANCE] = Fp::from(10);
    rebind(&mut all_available);
    assert!(accepts(&all_available, false));
    let mut burned_spend = all_available;
    burned_spend.statement[19] += Fp::ONE;
    burned_spend.successor.core[core::BALANCE] -= Fp::ONE;
    rebind(&mut burned_spend);
    assert!(!accepts(&burned_spend, false));
    for index in [17, 18, 22, 25] {
        let mut wrong = honest;
        wrong.statement[index] += Fp::ONE;
        assert!(!accepts(&wrong, false), "effect {index}");
    }
    for (amount, charge, quote) in [(0, 0, 0), (30, 31, 43), (30, 0, 43), (30, 3, 0)] {
        let mut wrong = honest;
        wrong.statement[19..22].copy_from_slice(&[
            Fp::from(amount),
            Fp::from(charge),
            Fp::from(quote),
        ]);
        wrong.successor.core[core::BALANCE] = Fp::from(100 - amount);
        rebind(&mut wrong);
        assert!(
            !accepts(&wrong, false),
            "amount={amount}, charge={charge}, quote={quote}"
        );
    }
    let mut free = honest;
    free.statement[20..22].fill(Fp::ZERO);
    assert!(accepts(&free, false));
    for index in [core::SEQUENCE, core::NEXT_REDEEM] {
        let mut wrong = honest;
        wrong.predecessor.core[index] = Fp::from_u128(u128::MAX);
        wrong.successor.core[index] = Fp::ZERO;
        if index == core::NEXT_REDEEM {
            wrong.statement[18] = Fp::from_u128(u128::MAX);
        }
        rebind(&mut wrong);
        assert!(!accepts(&wrong, false), "counter {index}");
    }
}

#[test]
fn retiring_is_one_way_and_has_no_monetary_effect() {
    let honest = witness(true);
    for index in 17..26 {
        let mut wrong = honest;
        wrong.statement[index] = Fp::ONE;
        assert!(!accepts(&wrong, true), "effect {index}");
    }
    let mut repeated = honest;
    repeated.predecessor.core[core::LIFECYCLE] = Fp::from(2);
    rebind(&mut repeated);
    assert!(!accepts(&repeated, true));
    let mut reversed = honest;
    reversed.predecessor.core[core::LIFECYCLE] = Fp::from(2);
    reversed.successor.core[core::LIFECYCLE] = Fp::ONE;
    rebind(&mut reversed);
    assert!(!accepts(&reversed, true));
}

fn prove<C: Circuit<Fp>>(circuit: &C, public: &[Vec<Fp>], seed: u8) {
    let params = common::vesta_params(K);
    let key = keygen_pk_v2(
        &params,
        circuit,
        &KeygenConfigV2::pipa_r(UnloadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, circuit, public).unwrap(),
        common::recovery(seed),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    assert_eq!(opening.g(), proof.opening.g());
    assert!(proof.proof.len() <= 3456);
    eprintln!(
        "{}: {} proof bytes",
        std::any::type_name::<C>(),
        proof.proof.len()
    );
    let mut wrong = public.to_vec();
    wrong[0][0] += Fp::ONE;
    assert!(
        accumulate_generator(
            &params,
            key.binding(),
            key.vk(),
            &wrong,
            &proof.proof,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    let mut corrupted = proof.proof;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(
        accumulate_generator(
            &params,
            key.binding(),
            key.vk(),
            public,
            &corrupted,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
}

#[test]
fn native_consuming_proofs_verify_complete_openings_and_reject_mutations() {
    let unload = UnloadCircuit::new(&witness(false));
    prove(&unload, &unload.instances(), 197);
    let retiring = RetiringCircuit::new(&witness(true));
    assert_eq!(
        RetiringCircuit::instance_types(),
        UnloadCircuit::instance_types()
    );
    prove(&retiring, &retiring.instances(), 198);
}

fn archive_witness() -> ArchiveWitness {
    let mut source = witness(false);
    source.successor = source.predecessor;
    source.successor.core[core::SEQUENCE] += Fp::ONE;
    source.successor.core[core::STATE_NONCE] += Fp::ONE;
    source.successor.core[core::PENDING_OUTGOING_ROOT] = Fp::from(103);
    source.statement[16] = Fp::from(5);
    source.statement[17..].fill(Fp::ZERO);
    source.statement[17] = Fp::from(105);
    source.statement[18] = Fp::from(107);
    rebind(&mut source);
    source.statement[12..14].fill(Fp::ZERO);
    ArchiveWitness {
        predecessor: source.predecessor,
        successor: source.successor,
        statement: source.statement,
    }
}

fn rebind_archive(w: &mut ArchiveWitness) {
    let mut source = ConsumingWitness {
        predecessor: w.predecessor,
        successor: w.successor,
        statement: w.statement,
    };
    rebind(&mut source);
    source.statement[12..14].fill(Fp::ZERO);
    w.predecessor = source.predecessor;
    w.successor = source.successor;
    w.statement = source.statement;
}

fn accepts_archive(w: &ArchiveWitness) -> bool {
    let circuit = ArchiveCircuit::new(w);
    check_circuit(&circuit, K, &circuit.instances(), CheckMode::Strict)
        .is_ok_and(|report| report.is_satisfied())
}

#[test]
fn archive_leaf_preserves_value_counters_credentials_and_held_policy() {
    let honest = archive_witness();
    let circuit = ArchiveCircuit::new(&honest);
    assert!(accepts_archive(&honest));
    shape(&circuit, &circuit.instances());
    for index in 0..33 {
        if [core::STATE_NONCE, core::PENDING_OUTGOING_ROOT].contains(&index) {
            continue;
        }
        let mut wrong = honest;
        wrong.successor.core[index] += Fp::ONE;
        rebind_archive(&mut wrong);
        assert!(!accepts_archive(&wrong), "Archive rehashed core {index}");
    }
    for index in 0..8 {
        let mut wrong = honest;
        wrong.successor.rest[index] += Fp::ONE;
        rebind_archive(&mut wrong);
        assert!(!accepts_archive(&wrong), "Archive rehashed rest {index}");
    }
    for index in [14, 16] {
        let mut wrong = honest;
        wrong.successor.lineage[index] += Fp::ONE;
        assert!(!accepts_archive(&wrong), "Archive lineage {index}");
    }
    // Both adjusted-root branches are left to A's authenticated evidence and
    // removal constraints. The private core's removal never changes the balance.
    let mut removed = honest;
    removed.successor.lineage[15] = Fp::from(109);
    assert!(accepts_archive(&removed));
    for index in [17, 18] {
        let mut wrong = honest;
        wrong.statement[index] = Fp::ZERO;
        assert!(!accepts_archive(&wrong));
    }
    for index in 19..26 {
        let mut wrong = honest;
        wrong.statement[index] = Fp::ONE;
        assert!(!accepts_archive(&wrong));
    }
}

#[test]
fn native_archive_leaf_verifies_complete_opening_and_rejects_mutations() {
    let circuit = ArchiveCircuit::new(&archive_witness());
    assert_eq!(
        ArchiveCircuit::instance_types(),
        UnloadCircuit::instance_types()
    );
    prove(&circuit, &circuit.instances(), 199);
}

macro_rules! installed_consuming_case {
    ($test:ident, $owner:ident, $circuit:ident, $retiring:literal, $seed:literal) => {
        #[test]
        fn $test() {
            use iroha_kagemusha_proof::admin_sigma::native::$owner;
            use iroha_plonk::keys::{CosetCachePolicy, pk::artifact::ReadConfig};
            let witness = witness($retiring);
            let circuit = $circuit::new(&witness);
            let params = common::vesta_params(K);
            let key = keygen_pk_v2(
                &params,
                &circuit,
                &KeygenConfigV2::pipa_r($circuit::instance_types().to_vec()),
            )
            .unwrap();
            let original = key.artifact_bytes_v2().unwrap();
            let installed = $owner::from_original_artifact(
                params,
                key.binding().encoded(),
                key.vk().to_bytes(),
                &original,
                ReadConfig {
                    maximum_bytes: original.len(),
                    maximum_rows: 1 << K,
                    coset_cache: CosetCachePolicy::OnDemand,
                    msm_budget: MemoryBudget::DEFAULT,
                },
            )
            .unwrap();
            assert_eq!(installed.binding(), key.binding());
            assert_eq!(installed.verifying_key().to_bytes(), key.vk().to_bytes());
            assert_eq!(
                installed.proving_key().artifact_bytes_v2().unwrap(),
                original
            );
            let proof = installed
                .prove(&witness, common::recovery($seed), ProverConfig::default())
                .unwrap();
            assert_eq!(proof.instances, circuit.instances());
            let opening = accumulate_generator(
                installed.params(),
                installed.binding(),
                installed.verifying_key(),
                &proof.instances,
                &proof.bytes,
                MemoryBudget::DEFAULT,
            )
            .unwrap();
            opening
                .decide(installed.params(), MemoryBudget::DEFAULT)
                .unwrap();
            let mut wrong = proof.instances.clone();
            wrong[0][0] += Fp::ONE;
            assert!(
                accumulate_generator(
                    installed.params(),
                    installed.binding(),
                    installed.verifying_key(),
                    &wrong,
                    &proof.bytes,
                    MemoryBudget::DEFAULT,
                )
                .is_err()
            );
            let mut corrupted = proof.bytes;
            let last = corrupted.len() - 1;
            corrupted[last] ^= 1;
            assert!(
                accumulate_generator(
                    installed.params(),
                    installed.binding(),
                    installed.verifying_key(),
                    &proof.instances,
                    &corrupted,
                    MemoryBudget::DEFAULT,
                )
                .is_err()
            );
            let mut wrong = witness;
            wrong.successor.core[core::BALANCE] += Fp::ONE;
            rebind(&mut wrong);
            assert!(
                installed
                    .prove(&wrong, common::recovery($seed + 1), ProverConfig::default())
                    .is_err()
            );
        }
    };
}

installed_consuming_case!(
    installed_admin_sigma_originals_prove_unload_and_reject_rehashed_value,
    UnloadProver,
    UnloadCircuit,
    false,
    205
);
installed_consuming_case!(
    installed_admin_sigma_originals_prove_retiring_and_reject_rehashed_value,
    RetiringProver,
    RetiringCircuit,
    true,
    207
);
