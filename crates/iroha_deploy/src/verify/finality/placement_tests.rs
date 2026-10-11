//! Exact retained witness reuse preserves independent placement and fresh member admission.

use super::*;
use norito::core::DecodeBudgetContext;

// The original native placement recipe is an independent regression oracle.
fn independently_place(
    prefix: &Prefix,
    proof: &SumeragiFinalityProof,
    epoch: u64,
) -> Result<AttestedTip, FinalityError> {
    let verified = prefix.native.verify_retained_decision(proof)?;
    if verified.commitment().schedule.current.authorization.epoch < epoch.saturating_sub(1) {
        return Err(FinalityError::OutsideRetainedPrefix {
            checkpoint: prefix.height(),
            height: proof.height(),
        });
    }
    Ok(AttestedTip {
        height: proof.block_header.height(),
        block_hash: proof.block_header.hash(),
    })
}

fn epoch(prefix: &Prefix) -> u64 {
    prefix
        .verified
        .commitment()
        .schedule
        .current
        .authorization
        .epoch
}

fn assert_same_refusal(prefix: &Prefix, proof: &SumeragiFinalityProof) {
    assert_ne!(proof, &prefix.tip);
    let expected = independently_place(prefix, proof, epoch(prefix)).unwrap_err();
    let actual = prefix.place(proof, epoch(prefix), None).unwrap_err();
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

#[test]
fn exact_tip_and_alternate_certificate_keep_native_placement_results() {
    let chain = Chain::new(&[(0..4, 3), (0..7, 7)], 5);
    for height in [1, 2, 3, 4] {
        let checkpoint = chain.verifier_at(height).checkpoint().clone();
        let mut prefix = Prefix::new(&checkpoint).unwrap();
        let expected = independently_place(&prefix, &prefix.tip, epoch(&prefix)).unwrap();
        assert_eq!(
            prefix.place(&prefix.tip, epoch(&prefix), None).unwrap(),
            expected
        );
        assert_eq!(expected.height.get(), height);
        let retained = prefix.tip.clone();
        prefix.push(chain.proof(height + 1)).unwrap();
        assert_eq!(
            prefix.place(&prefix.tip, epoch(&prefix), None).unwrap(),
            independently_place(&prefix, &prefix.tip, epoch(&prefix)).unwrap()
        );
        assert_eq!(
            prefix.place(&retained, epoch(&prefix), None).unwrap(),
            independently_place(&prefix, &retained, epoch(&prefix)).unwrap()
        );
        let alternate = chain.alternate(height + 1);
        assert_ne!(alternate, prefix.tip);
        assert_eq!(
            alternate.block_header.hash(),
            prefix.tip.block_header.hash()
        );
        assert_eq!(
            prefix.place(&alternate, epoch(&prefix), None).unwrap(),
            independently_place(&prefix, &alternate, epoch(&prefix)).unwrap()
        );
        // The same block with a different corrupt QC must never inherit the exact tip verdict.
        let mut invalid = alternate;
        let header = core(&invalid);
        let execution = result(&invalid);
        let mut qc = commit_qc(&invalid);
        qc.agg_sig.0[0] ^= 1;
        replace_certificate(&mut invalid, &header, &qc, &execution);
        assert_eq!(invalid.block_header.hash(), prefix.tip.block_header.hash());
        assert_same_refusal(&prefix, &invalid);
        assert_eq!(prefix.tip, *chain.proof(height + 1));
    }
}

#[test]
fn every_complete_witness_field_remains_bound_to_the_native_tip() {
    let chain = Chain::constant(4, 3);
    let checkpoint = chain.verifier_at(3).checkpoint().clone();
    let prefix = Prefix::new(&checkpoint).unwrap();
    let original = checkpoint.encode_canonical().unwrap();
    let mut changed_header = prefix.tip.clone();
    changed_header.block_header = BlockHeader::new(
        nz(3),
        Some(chain.proof(2).block_header.hash()),
        None,
        300,
        0,
    );
    let mut changed_wire = prefix.tip.clone();
    changed_wire.block_wire.push(0);
    let mut changed_committee = prefix.tip.clone();
    changed_committee.committee[0].public_key = key(42).public_key().clone();
    let mut changed_pop = prefix.tip.clone();
    changed_pop.committee[0].proof_of_possession[0] ^= 1;
    for changed in [changed_header, changed_wire, changed_committee, changed_pop] {
        assert_same_refusal(&prefix, &changed);
    }
    assert_eq!(
        prefix.checkpoint().unwrap().encode_canonical().unwrap(),
        original
    );
    assert_eq!(
        prefix.place(&prefix.tip, epoch(&prefix), None).unwrap(),
        independently_place(&prefix, &prefix.tip, epoch(&prefix)).unwrap()
    );
}

#[test]
fn exact_tip_reuse_keeps_prior_failure_height_and_epoch_guards() {
    let chain = Chain::constant(4, 6);
    let prefix = Prefix::new(chain.verifier_at(5).checkpoint()).unwrap();
    assert!(matches!(
        prefix.place(
            &prefix.tip,
            epoch(&prefix),
            Some(FinalityError::WrongGenesis)
        ),
        Err(FinalityError::WrongGenesis)
    ));
    // A prior resource cap cannot turn an already retained exact tip into a future claim.
    assert_eq!(
        prefix
            .place(
                &prefix.tip,
                epoch(&prefix),
                Some(FinalityError::ResourceLimit("proof count")),
            )
            .unwrap(),
        independently_place(&prefix, &prefix.tip, epoch(&prefix)).unwrap()
    );
    assert!(matches!(
        prefix.place(chain.proof(6), epoch(&prefix), None),
        Err(FinalityError::AheadOfCheckpoint {
            checkpoint: 5,
            height: 6
        })
    ));
    assert!(matches!(
        prefix.place(
            chain.proof(6),
            epoch(&prefix),
            Some(FinalityError::ResourceLimit("proof count")),
        ),
        Err(FinalityError::ResourceLimit("proof count"))
    ));
    assert!(matches!(
        prefix.place(chain.proof(3), epoch(&prefix), None),
        Err(FinalityError::OutsideRetainedPrefix {
            checkpoint: 5,
            height: 3
        })
    ));
    assert!(matches!(
        prefix.place(&prefix.tip, epoch(&prefix) + 2, None),
        Err(FinalityError::OutsideRetainedPrefix {
            checkpoint: 5,
            height: 5
        })
    ));
}

#[test]
fn identical_tip_never_reuses_a_members_challenge_identity_or_signature() {
    let chain = Chain::constant(4, 3);
    let original = chain.verifier_at(3).checkpoint().clone();
    let members = &chain.epoch(3).keys;
    for mutation in 0..4 {
        let mut verifier = chain.verifier_at(3);
        let mut source = Source::new(&chain);
        for (index, member) in members.iter().take(2).enumerate() {
            let mut statement = chain.attest(member, 3);
            match mutation {
                0 => {
                    statement.body.challenge = [9; 32];
                    resign(&mut statement, member);
                }
                1 => {
                    statement.body.network_id = NetworkId::from_genesis_hash(
                        HashOf::from_untyped_unchecked(Hash::new(b"foreign attestation network")),
                    );
                    resign(&mut statement, member);
                }
                2 => {
                    statement.body.build_fingerprint = Hash::new(b"unsigned statement mutation");
                }
                _ => statement = chain.attest(&members[(index + 1) % members.len()], 3),
            }
            assert_eq!(statement.body.finality_proof, *original.tip());
            source.attestation_overrides.insert(peer(member), statement);
        }
        let Err(FinalityError::InsufficientAttestations(report)) =
            verifier.observe(&source, &CHALLENGE)
        else {
            panic!("identical certified blocks cannot authenticate two invalid fresh statements")
        };
        assert_eq!(report.verified(), 2);
        assert_eq!(verifier.checkpoint(), &original);
        let fresh = verifier.observe(&Source::new(&chain), &CHALLENGE).unwrap();
        assert_eq!((fresh.height.get(), fresh.verified()), (3, 4));
    }
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn exact_tip_placement_preserves_active_decoder_charges_and_refusals() {
    let chain = Chain::constant(4, 3);
    let prefix = Prefix::new(chain.verifier_at(3).checkpoint()).unwrap();
    const CEILING: usize = 64 * 1024 * 1024;
    let expected_budget = DecodeBudgetContext::new(limits(CEILING));
    let expected = expected_budget
        .with(|| independently_place(&prefix, &prefix.tip, epoch(&prefix)))
        .unwrap();
    let expected_cost = usize::try_from(expected_budget.consumed_allocated_bytes()).unwrap();
    assert!(expected_cost > 1 && expected_cost <= CEILING);
    let actual_budget = DecodeBudgetContext::new(limits(CEILING));
    let actual = actual_budget
        .with(|| prefix.place(&prefix.tip, epoch(&prefix), None))
        .unwrap();
    assert_eq!(actual, expected);
    // Each native invocation owns a separately allocated decoded graph. Norito
    // charges realignment copies when their source address requires them, so a
    // successful invocation's total is neither a minimum nor an equality oracle
    // for another graph. Both must still perform positive, finite charged work.
    let actual_cost = usize::try_from(actual_budget.consumed_allocated_bytes()).unwrap();
    assert!(actual_cost > 1 && actual_cost <= CEILING);
    for cap in [0, 1] {
        let expected_budget = DecodeBudgetContext::new(limits(cap));
        let expected_error = expected_budget
            .with(|| independently_place(&prefix, &prefix.tip, epoch(&prefix)))
            .expect_err("native signed-block decoding cannot fit a zero/one-byte budget");
        let actual_budget = DecodeBudgetContext::new(limits(cap));
        let actual_error = actual_budget
            .with(|| prefix.place(&prefix.tip, epoch(&prefix), None))
            .expect_err("an active owner must still refuse the exact retained tip");
        // Both calls borrow the same original frame and refuse before creating
        // a decoded graph: even one compact public key needs payload_bytes + 1.
        assert_eq!(
            format!("{actual_error:?}"),
            format!("{expected_error:?}"),
            "placement refusal differs at allocation cap {cap}"
        );
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes(),
            "placement charges differ at allocation cap {cap}"
        );
    }
    assert_eq!(
        prefix.place(&prefix.tip, epoch(&prefix), None).unwrap(),
        expected
    );
}
