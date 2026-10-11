//! Successful observations retain only their exact authenticated tip in the existing owner.

use super::*;
use norito::core::DecodeBudgetContext;

fn selected_source(chain: &Chain, height: u64) -> Source<'_> {
    let mut source = Source::new(chain);
    source.served = height;
    for key in &chain.epoch(height).keys {
        source.tips.insert(peer(key), height);
    }
    source
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn observed_tip_is_exact_shared_and_invalidated_by_independent_advancement() {
    let chain = Chain::constant(4, 4);
    let mut verifier = chain.verifier_at(2);
    assert_eq!(verifier.verified_tip().unwrap().height(), 2);
    let before = verifier.clone();
    let report = verifier
        .observe(&selected_source(&chain, 3), &CHALLENGE)
        .unwrap();
    assert_eq!((report.height.get(), report.verified()), (3, 4));
    let retained = verifier
        .verified_tip
        .get()
        .expect("successful observation retains its tip");
    assert_eq!(retained.height(), 3);
    assert_eq!(retained.header().hash(), report.block_hash);
    assert_eq!(
        retained.block().encode_wire().unwrap(),
        chain.proof(3).block_wire
    );
    assert_eq!(verifier.checkpoint(), chain.verifier_at(3).checkpoint());
    assert!(!Arc::ptr_eq(&verifier.checkpoint, &before.checkpoint));
    assert!(!Arc::ptr_eq(&verifier.verified_tip, &before.verified_tip));
    assert_eq!(before.verified_tip_ref().unwrap().height(), 2);
    let borrowed = norito::with_decode_limits_scope(limits(0), || verifier.verified_tip_ref())
        .expect("already authenticated exact tip needs no second checkpoint import");
    assert!(std::ptr::eq(borrowed, retained));

    let mut advanced = verifier.clone();
    assert!(Arc::ptr_eq(&verifier.verified_tip, &advanced.verified_tip));
    advanced
        .advance(&Source::new(&chain), chain.proof(4))
        .unwrap();
    assert_eq!(advanced.checkpoint().height(), 4);
    assert!(!Arc::ptr_eq(&verifier.checkpoint, &advanced.checkpoint));
    assert!(!Arc::ptr_eq(&verifier.verified_tip, &advanced.verified_tip));
    assert!(advanced.verified_tip.get().is_none());
    assert!(matches!(
        norito::with_decode_limits_scope(limits(0), || advanced.verified_tip_ref()),
        Err(FinalityError::DecodeResource(_))
    ));
    assert!(std::ptr::eq(retained, verifier.verified_tip_ref().unwrap()));
    assert_eq!(advanced.verified_tip().unwrap().height(), 4);
    assert_eq!(retained.height(), 3);
}

#[test]
fn observation_refusals_and_pending_progress_keep_the_original_tip_owner() {
    let chain = Chain::constant(4, 5);
    let mut verifier = chain.verifier_at(2);
    verifier
        .observe(&selected_source(&chain, 2), &CHALLENGE)
        .unwrap();
    let original = verifier.clone();
    let tip = original.verified_tip_ref().unwrap();
    assert!(matches!(
        verifier.observe(&Source::new(&chain), &[0; 32]),
        Err(FinalityError::ZeroChallenge)
    ));
    let mut malformed = chain.alternate(2);
    let mut qc = commit_qc(&malformed);
    qc.agg_sig.0[0] ^= 1;
    let header = core(&malformed);
    let execution = result(&malformed);
    replace_certificate(&mut malformed, &header, &qc, &execution);
    let mut source = selected_source(&chain, 2);
    for key in &chain.epoch(2).keys {
        let mut attestation = chain.attest(key, 2);
        attestation.body.finality_proof = malformed.clone();
        resign(&mut attestation, key);
        source.attestation_overrides.insert(peer(key), attestation);
    }
    assert!(matches!(
        verifier.observe(&source, &CHALLENGE),
        Err(FinalityError::InsufficientAttestations(_))
    ));
    assert!(matches!(
        verifier.advance(&Source::new(&chain), &malformed),
        Err(FinalityError::Native(_))
    ));
    assert_eq!(verifier.checkpoint(), original.checkpoint());
    assert!(Arc::ptr_eq(&verifier.verified_tip, &original.verified_tip));
    assert!(std::ptr::eq(tip, verifier.verified_tip_ref().unwrap()));

    let result = verifier.observe_with_budget(
        &Source::new(&chain),
        &CHALLENGE,
        &mut Budget {
            proofs: 1,
            bytes: MAX_ADVANCE_BYTES,
        },
    );
    assert!(matches!(
        result,
        Err(FinalityError::CatchingUp {
            verified: 3,
            claimed: 5
        })
    ));
    assert_eq!(verifier.pending.as_ref().unwrap().height(), 3);
    assert_eq!(verifier.checkpoint(), original.checkpoint());
    assert!(Arc::ptr_eq(&verifier.verified_tip, &original.verified_tip));
    assert!(std::ptr::eq(tip, verifier.verified_tip_ref().unwrap()));
    assert!(verifier.promote_verified_progress());
    assert_eq!(verifier.checkpoint().height(), 3);
    assert!(verifier.verified_tip.get().is_none());
    assert!(matches!(
        norito::with_decode_limits_scope(limits(0), || verifier.verified_tip_ref()),
        Err(FinalityError::DecodeResource(_))
    ));
    assert_eq!(original.verified_tip_ref().unwrap().height(), 2);
}

#[test]
fn active_decoder_observation_preserves_cold_tip_and_allocation_refusals() {
    let chain = Chain::constant(4, 3);
    let mut verifier = chain.verifier_at(2);
    verifier
        .observe(&selected_source(&chain, 2), &CHALLENGE)
        .unwrap();
    assert!(verifier.verified_tip.get().is_some());
    let before = verifier.clone();
    let source = selected_source(&chain, 3);
    let budget = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let report = budget
        .with(|| verifier.observe(&source, &CHALLENGE))
        .unwrap();
    assert_eq!((report.height.get(), report.verified()), (3, 4));
    assert!(budget.consumed_allocated_bytes() > 0);
    assert_eq!(verifier.checkpoint(), chain.verifier_at(3).checkpoint());
    assert!(verifier.verified_tip.get().is_none());
    assert!(!Arc::ptr_eq(&verifier.verified_tip, &before.verified_tip));
    assert!(matches!(
        norito::with_decode_limits_scope(limits(0), || verifier.verified_tip_ref()),
        Err(FinalityError::DecodeResource(_))
    ));
    assert!(verifier.verified_tip.get().is_none());
    let cold = verifier.clone();
    assert!(
        norito::with_decode_limits_scope(limits(0), || { verifier.observe(&source, &CHALLENGE) })
            .is_err()
    );
    assert_eq!(verifier.checkpoint(), cold.checkpoint());
    assert!(Arc::ptr_eq(&verifier.verified_tip, &cold.verified_tip));
    assert!(verifier.verified_tip.get().is_none());
    assert_eq!(before.verified_tip_ref().unwrap().height(), 2);
    verifier.observe(&source, &CHALLENGE).unwrap();
    assert!(verifier.verified_tip.get().is_some());
    let tip = norito::with_decode_limits_scope(limits(0), || verifier.verified_tip_ref()).unwrap();
    assert_eq!(tip.height(), 3);
    assert_eq!(tip.header().hash(), chain.proof(3).block_header.hash());
}
