//! Complete checkpoint-tip handoff preserves native prefix verification and decoder admission.

use super::*;
use norito::core::DecodeBudgetContext;

// Exact pre-handoff recipe, retained only as an independent regression oracle.
fn original_prefix(checkpoint: &SumeragiFinalityCheckpoint) -> Result<Prefix, FinalityError> {
    let native = SumeragiFinalityVerifier::from_trusted_checkpoint(
        checkpoint,
        &checkpoint.network_id(),
        checkpoint.chain_id(),
    )?;
    let verified = native.verify_retained_decision(checkpoint.tip())?;
    Ok(Prefix {
        native,
        tip: checkpoint.tip().clone(),
        verified,
        start: checkpoint.height(),
    })
}

fn same_prefix(actual: &Prefix, expected: &Prefix) {
    assert_eq!(actual.start, expected.start);
    assert_eq!(actual.height(), expected.height());
    assert_eq!(actual.tip, expected.tip);
    assert_eq!(actual.members().unwrap(), expected.members().unwrap());
    assert_eq!(actual.verified.commitment(), expected.verified.commitment());
    assert_eq!(actual.verified.context_id(), expected.verified.context_id());
    assert_eq!(
        actual.verified.block().encode_wire().unwrap(),
        expected.verified.block().encode_wire().unwrap()
    );
    assert_eq!(actual.checkpoint().unwrap(), expected.checkpoint().unwrap());
}

#[test]
fn prefix_import_preserves_native_tip_successor_and_member_witness_checks() {
    let chain = Chain::new(&[(0..4, 3), (0..7, 7)], 5);
    for height in [1, 2, 3] {
        let checkpoint = chain.verifier_at(height).checkpoint().clone();
        let original_bytes = checkpoint.encode_canonical().unwrap();
        let mut actual = Prefix::new(&checkpoint).unwrap();
        let mut expected = original_prefix(&checkpoint).unwrap();
        same_prefix(&actual, &expected);
        assert_eq!(actual.checkpoint().unwrap(), checkpoint);
        actual.push(chain.proof(height + 1)).unwrap();
        expected.push(chain.proof(height + 1)).unwrap();
        same_prefix(&actual, &expected);
        let epoch = actual
            .verified
            .commitment()
            .schedule
            .current
            .authorization
            .epoch;
        let alternate = chain.alternate(height + 1);
        assert_eq!(
            actual.place(&alternate, epoch, None).unwrap(),
            expected.place(&alternate, epoch, None).unwrap()
        );
        let mut malformed = alternate;
        let mut qc = commit_qc(&malformed);
        qc.agg_sig.0[0] ^= 1;
        let header = core(&malformed);
        let execution = result(&malformed);
        replace_certificate(&mut malformed, &header, &qc, &execution);
        let actual_error = actual.place(&malformed, epoch, None).unwrap_err();
        let expected_error = expected.place(&malformed, epoch, None).unwrap_err();
        assert!(matches!(actual_error, FinalityError::Native(_)));
        assert_eq!(format!("{actual_error:?}"), format!("{expected_error:?}"));
        same_prefix(&actual, &expected);
        assert_eq!(checkpoint.encode_canonical().unwrap(), original_bytes);
    }
}

#[test]
fn prefix_import_refuses_a_foreign_retained_decision_without_replacing_its_source() {
    let chain = Chain::constant(4, 2);
    let foreign = Chain::new(&[(10..14, 5)], 2);
    let checkpoint = chain.verifier().checkpoint().clone();
    let original_bytes = checkpoint.encode_canonical().unwrap();
    // This API builds untrusted restart data. Each proof is individually well-formed,
    // but the foreign height-two committee cannot replace the selected signed genesis.
    let malformed = checkpoint
        .with_independently_authenticated_decision_data(&[
            chain.proof(1).clone(),
            foreign.proof(2).clone(),
        ])
        .unwrap();
    let malformed_bytes = malformed.encode_canonical().unwrap();
    for _ in 0..2 {
        let actual = Prefix::new(&malformed)
            .err()
            .expect("foreign decision refused");
        let expected = original_prefix(&malformed).err().expect("original refusal");
        assert!(matches!(actual, FinalityError::Native(_)));
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        assert_eq!(malformed.encode_canonical().unwrap(), malformed_bytes);
    }
    same_prefix(
        &Prefix::new(&checkpoint).unwrap(),
        &original_prefix(&checkpoint).unwrap(),
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original_bytes);
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn prefix_import_preserves_active_owner_work_and_allocation_refusal() {
    let chain = Chain::constant(4, 2);
    let checkpoint = chain.verifier_at(2).checkpoint().clone();
    let original_bytes = checkpoint.encode_canonical().unwrap();
    const CEILING: usize = 64 * 1024 * 1024;
    let import_budget = DecodeBudgetContext::new(limits(CEILING));
    let imported = import_budget
        .with(|| {
            SumeragiFinalityVerifier::from_trusted_checkpoint(
                &checkpoint,
                &checkpoint.network_id(),
                checkpoint.chain_id(),
            )
        })
        .unwrap();
    let import_cost = usize::try_from(import_budget.consumed_allocated_bytes()).unwrap();
    assert!(import_cost > 1 && import_cost < CEILING);
    import_budget
        .with(|| imported.verify_retained_decision(checkpoint.tip()))
        .unwrap();
    let after_tip_read = usize::try_from(import_budget.consumed_allocated_bytes()).unwrap();
    assert!(after_tip_read > import_cost && after_tip_read <= CEILING);
    let original_budget = DecodeBudgetContext::new(limits(CEILING));
    let expected = original_budget
        .with(|| original_prefix(&checkpoint))
        .unwrap();
    let original_cost = usize::try_from(original_budget.consumed_allocated_bytes()).unwrap();
    assert!(original_cost > 1 && original_cost <= CEILING);
    let actual_budget = DecodeBudgetContext::new(limits(CEILING));
    let actual = actual_budget.with(|| Prefix::new(&checkpoint)).unwrap();
    let actual_cost = usize::try_from(actual_budget.consumed_allocated_bytes()).unwrap();
    // These separate imports own different decoded allocations. Conditional
    // realignment can change their work totals; each must do positive charged
    // work within its original finite budget and produce the same prefix.
    assert!(actual_cost > 1 && actual_cost <= CEILING);
    same_prefix(&actual, &expected);

    // Both limits refuse on the original borrowed input, before a complete
    // decoded graph exists: even one compact public key needs payload_bytes + 1.
    for cap in [0, 1] {
        let expected_budget = DecodeBudgetContext::new(limits(cap));
        let expected_error = expected_budget
            .with(|| original_prefix(&checkpoint))
            .err()
            .expect("original resource refusal");
        let actual_budget = DecodeBudgetContext::new(limits(cap));
        let actual_error = actual_budget
            .with(|| Prefix::new(&checkpoint))
            .err()
            .expect("same caller resource refusal");
        assert_eq!(
            format!("{actual_error:?}"),
            format!("{expected_error:?}"),
            "prefix refusal differs at allocation cap {cap}"
        );
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes(),
            "prefix charges differ at allocation cap {cap}"
        );
    }
    same_prefix(&Prefix::new(&checkpoint).unwrap(), &expected);
    assert_eq!(checkpoint.encode_canonical().unwrap(), original_bytes);
}
