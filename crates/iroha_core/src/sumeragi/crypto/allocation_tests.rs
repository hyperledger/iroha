//! Pairing allocator provenance and allocation-free dynamic verification.

use super::*;
use crate::test_allocations::{allocations_during, refuse_one_layout_during};
use std::alloc::Layout;

fn pairing_layout() -> Layout {
    ConsensusAggregateScratch::<()>::backing_layout()
}

#[test]
fn query_pairing_allocator_refusal_keeps_physical_cause_without_release_wait() {
    let pairs: Vec<_> = (1..=4).map(tests::key_pair).collect();
    let members = tests::query_members(&pairs);
    let layout = pairing_layout();
    let mut admitted = 0;
    let (result, observed) = refuse_one_layout_during(layout, || {
        BlsCrypto::for_query_committee(&members, &mut |bytes| {
            admitted += bytes;
            Ok(())
        })
    });
    assert!(observed);
    let QueryCommitteeError::Resource(original) = result.unwrap_err() else {
        panic!("pairing allocator refusal cannot become a bad-key verdict")
    };
    assert_eq!(
        admitted,
        query_committee_allocation_bytes(&members).unwrap()
    );
    assert!(original.allocation_refusal().is_none());
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert_eq!(
        original
            .allocator_refusal()
            .unwrap()
            .vec_reserve_error()
            .unwrap()
            .1,
        layout
    );
    assert!(BlsCrypto::for_query_committee(&members, &mut |_| Ok(())).is_ok());
}

#[test]
fn dynamic_aggregate_relations_use_no_heap_pairing_allocation() {
    let pairs: Vec<_> = (1..=4).map(tests::key_pair).collect();
    let members = tests::query_members(&pairs);
    let crypto = BlsCrypto::new();
    crypto
        .admit_committee(members.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .unwrap();
    let signers: Vec<_> = pairs
        .iter()
        .map(|pair| KeyPairSigner::new(pair).unwrap())
        .collect();
    let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
    let a = tests::message(1);
    let b = tests::message(2);
    let same: Vec<_> = signers
        .iter()
        .map(|signer| signer.sign(&a).unwrap())
        .collect();
    let aggregate = crypto.aggregate(&same).unwrap();
    let groups = vec![
        (keys[..2].to_vec(), a.clone()),
        (keys[2..].to_vec(), b.clone()),
    ];
    let different: Vec<_> = signers
        .iter()
        .enumerate()
        .map(|(i, signer)| signer.sign(if i < 2 { &a } else { &b }).unwrap())
        .collect();
    let grouped = crypto.aggregate(&different).unwrap();
    drop(crypto.admitted.read());
    let (verdicts, refused) = refuse_one_layout_during(pairing_layout(), || {
        let mut verdicts = [false; 4];
        assert_eq!(
            allocations_during(|| {
                verdicts[0] = crypto.verify_aggregate(&keys, &a, &aggregate);
                verdicts[1] = crypto.verify_aggregate(&keys, &b, &aggregate);
                verdicts[2] = crypto.verify_aggregate_multi(&groups, &grouped);
                verdicts[3] = crypto.verify_aggregate_multi(&groups, &aggregate);
            }),
            0
        );
        verdicts
    });
    assert_eq!(verdicts, [true, false, true, false]);
    assert!(
        !refused,
        "dynamic boolean relations do not invoke the pairing allocator"
    );
}

#[test]
fn unsupported_pairing_geometry_refuses_startup_and_query_scratch_locally() {
    // The linked build passes the same check that node startup enforces.
    assert_eq!(BlsCrypto::check_pairing_geometry(), Ok(()));
    assert_eq!(
        BlsCrypto::check_pairing_geometry(),
        consensus::check_pairing_geometry()
    );
    let refused =
        scratch_construction_error(consensus::AggregateScratchError::UnsupportedGeometry {
            context_bytes: 0,
        });
    assert_eq!(
        refused.reason(),
        ivm::error::ExecutionDeferral::VerifierInitializationUnavailable
    );
    assert!(refused.allocation_refusal().is_none());
    assert!(refused.allocator_refusal().is_none());
}

#[test]
fn dynamic_and_query_owned_timeout_relations_cross_the_pairing_flush() {
    // q = 9 timeout votes of an n = 13 committee with distinct high-QC views: nine pairing
    // terms, so blst folds one full eight-term buffer and commit folds the ninth.
    let pairs: Vec<_> = (1..=13).map(tests::key_pair).collect();
    let members = tests::query_members(&pairs);
    let dynamic = BlsCrypto::new();
    dynamic
        .admit_committee(members.iter().map(|member| {
            (
                member.validator.public_key(),
                member.proof_of_possession.as_slice(),
            )
        }))
        .unwrap();
    let owned = BlsCrypto::for_query_committee(&members, &mut |_| Ok(())).unwrap();
    let signers: Vec<_> = pairs
        .iter()
        .map(|pair| KeyPairSigner::new(pair).unwrap())
        .collect();
    let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
    let instance = Hash32([0x42; 32]);
    let epoch = iroha_sumeragi::types::EpochId {
        epoch: 7,
        context: Hash32([0x51; 32]),
    };
    let preimage = |high_qc_view: u64| {
        iroha_sumeragi::preimage::tmo_preimage(&instance, &epoch, 7, 20, Some(high_qc_view))
    };
    let groups: Vec<_> = (0..9_u64)
        .map(|view| (vec![keys[usize::try_from(view).unwrap()]], preimage(view)))
        .collect();
    let shares: Vec<_> = (0..9_u64)
        .map(|view| {
            signers[usize::try_from(view).unwrap()]
                .sign(&preimage(view))
                .unwrap()
        })
        .collect();
    let aggregate = dynamic.aggregate(&shares).unwrap();
    for crypto in [&dynamic, &owned] {
        assert!(crypto.verify_aggregate_multi(&groups, &aggregate));
        assert!(!crypto.verify_aggregate_multi(&groups[..8], &aggregate));
        for changed in [0, 8] {
            let mut altered = groups.clone();
            altered[changed].1 = preimage(77);
            assert!(!crypto.verify_aggregate_multi(&altered, &aggregate));
        }
        let mut reversed = groups.clone();
        reversed.reverse();
        assert!(crypto.verify_aggregate_multi(&reversed, &aggregate));
    }
    let mut verdict = false;
    assert_eq!(
        allocations_during(|| verdict = dynamic.verify_aggregate_multi(&groups, &aggregate)),
        0,
        "the dynamic stack relation allocates nothing past the flush"
    );
    assert!(verdict);
}
