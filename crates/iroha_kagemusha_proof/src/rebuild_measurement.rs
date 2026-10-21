//! Explicitly ignored real-family comparison; compiled only for unit tests.
//! No advice or original artifact is written. RSS is a lifetime high-water mark.

use std::time::Instant;

use ff::PrimeField;
use iroha_measurement::probe::ProcessSnapshot;
use iroha_pasta::{PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned_with_claim,
    frontend::Circuit,
    keys::{CosetCachePolicy, ProvingKey, SourceBoundViewV2, keygen_pk_from_vk_v2_cancellable},
    pcs::ipa::PinnedParams,
    prover::rebuild_key_and_witness_v2_cancellable,
    verifier::verify_full_opening_cancellable,
};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
struct PublicKeyIdentity {
    artifact: Vec<u8>,
    descriptor: Vec<u8>,
    copy_digest: [u8; 32],
    polynomial_digest: [u8; 32],
}

fn hash_column<F: PrimeField>(hash: &mut Sha256, column: &[F]) {
    hash.update(u64::try_from(column.len()).unwrap().to_le_bytes());
    for value in column {
        hash.update(value.to_repr().as_ref());
    }
}

// Only public fixed/selector/permutation/mask material is hashed. Lengths bind
// each group and column; this observation does not replace source admission.
fn key_identity<C: PastaCurve>(key: &ProvingKey<C>) -> PublicKeyIdentity {
    assert!(!key.has_coset_cache());
    let mut hash = Sha256::new();
    for columns in [
        key.fixed_values(),
        key.fixed_polys(),
        key.selector_values(),
        key.permutation_values(),
        key.permutation_polys(),
    ] {
        hash.update(u64::try_from(columns.len()).unwrap().to_le_bytes());
        for column in columns {
            hash_column(&mut hash, column);
        }
    }
    for (first, last, active) in [key.mask_values(), key.mask_polys()] {
        hash_column(&mut hash, first);
        hash_column(&mut hash, last);
        hash_column(&mut hash, active);
    }
    PublicKeyIdentity {
        artifact: key.artifact_bytes_v2().unwrap(),
        descriptor: key.binding().encoded().to_vec(),
        copy_digest: *key.copy_digest(),
        polynomial_digest: hash.finalize().into(),
    }
}

/// One separate/fused pair over the same admitted source, actual circuit and
/// public instances. Fresh hedged OS randomness is required for each proof.
/// Generic plonk unit tests, which can access private advice and test RNGs,
/// separately cover exact witness and seeded proof-byte equality.
pub(crate) fn compare<C, Ci, S>(
    label: &str,
    params: &PinnedParams<C>,
    metadata: &SourceBoundViewV2<'_, C>,
    source: impl Fn() -> S,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
    mut decide_carried_claims: impl FnMut(),
) where
    C: PastaCurve,
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
    S: Circuit<C::ScalarExt>,
{
    assert!(
        !cfg!(debug_assertions),
        "run real-family measurement with --release"
    );
    let mut first_key = None;
    let mut first_proof = None;
    // One pair per genuine fixture: raw observations, not a distribution or p95.
    // Separate always runs first; allocator/cache/order effects are not removed.
    for variant in ["separate", "fused"] {
        let before = ProcessSnapshot::capture().expect("required process probes");
        let started = Instant::now();
        let (key, witness) = if variant == "separate" {
            let source = source();
            let key = keygen_pk_from_vk_v2_cancellable(
                params,
                &source,
                metadata,
                CosetCachePolicy::OnDemand,
                None,
            )
            .unwrap();
            drop(source);
            let witness =
                Witness::from_circuit_cancellable(&key, circuit, instances, None).unwrap();
            (key, witness)
        } else {
            rebuild_key_and_witness_v2_cancellable(
                params,
                circuit,
                metadata,
                instances,
                CosetCachePolicy::OnDemand,
                None,
            )
            .unwrap()
        };
        // Preparation includes source construction for the separate path and
        // all synthesis/rebuild/witness work, excluding keygen and admission.
        let preparation_ns = started.elapsed().as_nanos();
        let after = ProcessSnapshot::capture().expect("required process probes");
        // ProcessSnapshot reads CPU before its other probes: this CPU delta
        // includes the first snapshot's RSS/load/thermal probe overhead.
        let preparation_cpu_ns = after.cpu_since(before).expect("monotonic process CPU");
        assert!(after.peak_rss_bytes >= before.peak_rss_bytes);
        assert_eq!(witness.instances(), instances);
        let identity = key_identity(&key);
        if let Some(expected) = &first_key {
            assert_eq!(
                &identity, expected,
                "exact metadata and public polynomial digest parity"
            );
        } else {
            first_key = Some(identity);
        }
        let started = Instant::now();
        let output = create_proof_owned_with_claim(
            params,
            &key,
            witness,
            ProverRandomness::hedged(),
            ProverConfig::default(),
        )
        .unwrap();
        drop(key); // No PK remains during verification or the next preparation.
        let proving_ns = started.elapsed().as_nanos();
        let started = Instant::now();
        let verified = verify_full_opening_cancellable(
            params,
            metadata.binding(),
            metadata.verifying_key(),
            instances,
            &output.proof,
            MemoryBudget::DEFAULT,
            None,
        )
        .unwrap();
        assert!(verified.matches(&output.opening));
        decide_carried_claims();
        let verification_ns = started.elapsed().as_nanos();
        if let Some(expected) = &first_proof {
            assert_ne!(
                &output.proof, expected,
                "fresh independent OS entropy for each proof"
            );
        } else {
            first_proof = Some(output.proof.clone());
        }
        // Neither the polynomial digest nor witness data is emitted.
        println!(
            "FUSED_REAL_FAMILY label={label} variant={variant} k={} workers={} preparation_ns={preparation_ns} preparation_process_cpu_probe_inclusive_ns={preparation_cpu_ns} proving_and_key_drop_ns={proving_ns} full_verification_and_claims_ns={verification_ns} proof_bytes={} kernel_lifetime_peak_rss_before={} kernel_lifetime_peak_rss_after={} load_before={:?} load_after={:?} thermal_before={:?} thermal_after={:?} public_instances_equal=true cross_variant_parity={} advice_equality_observed=false exact_proof_byte_parity=false randomness=fresh-hedged sample_count=1 device_p95=false",
            params.k(),
            rayon::current_num_threads(),
            output.proof.len(),
            before.peak_rss_bytes,
            after.peak_rss_bytes,
            before.load_milli,
            after.load_milli,
            before.thermal,
            after.thermal,
            if variant == "fused" {
                "verified"
            } else {
                "pending"
            },
        );
    }
    println!("FUSED_REAL_FAMILY_PAIR label={label} pair_verified=true");
}
