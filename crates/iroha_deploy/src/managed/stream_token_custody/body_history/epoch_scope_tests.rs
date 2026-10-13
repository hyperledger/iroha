//! Genuine standalone body parses preserve source custody and original active admission.

use super::*;
use crate::managed::service_authority::CheckpointImports;
use iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1;
use norito::core::DecodeBudgetContext;

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        MAX_ALL_BODY_BYTES,
        allocation,
        64,
    )
}

fn independent(owner: &ManagedStreamTokenCustody) -> Result<BodyHistory> {
    BodyHistory::open_with_imports(
        owner,
        CustodyPurpose::Renewal(2),
        &mut CheckpointImports::new(&owner.authority, None),
    )?
    .ok_or_else(|| ManagedBootstrapFailure::RetainedMaterial.into())
}

fn standalone(owner: &ManagedStreamTokenCustody) -> Result<BodyHistory> {
    BodyHistory::open(owner, CustodyPurpose::Renewal(2))?
        .ok_or_else(|| ManagedBootstrapFailure::RetainedMaterial.into())
}

fn assert_same(actual: &BodyHistory, expected: &BodyHistory) {
    assert_eq!(
        actual.selection.digest().unwrap(),
        expected.selection.digest().unwrap()
    );
    assert_eq!(actual.purpose, expected.purpose);
    assert_eq!(actual.bodies.len(), 2);
    assert_eq!(actual.bodies.len(), expected.bodies.len());
    assert_eq!(actual.anchor.highest, expected.anchor.highest);
    assert_eq!(actual.anchor.active, expected.anchor.active);
    assert_eq!(actual.anchor.completed, expected.anchor.completed);
    for (actual, expected) in actual.bodies.iter().zip(&expected.bodies) {
        assert_eq!(actual.semantic, expected.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            expected.reservation.digest().unwrap()
        );
    }
}

fn error<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("the original retained source or admission must refuse"),
        Err(error) => error.to_string(),
    }
}

// The existing optional cache clears after a genuine malformed canonical producer refuses.
// This obtains a cold import without a test-only cache mutation or altered production branch.
fn cold_imports(owner: &ManagedStreamTokenCustody) {
    assert!(owner.authority.decode_checkpoint(&[]).is_err());
}

fn epoch_projection(
    validation: &mut EpochValidationScope,
    context: &ValidatorEpochContextV1,
) -> iroha_sumeragi::types::EpochConfig {
    let budget = DecodeBudgetContext::new(limits(0));
    let projection = budget.with(|| validation.core_epoch(context)).unwrap();
    assert_eq!(budget.consumed_allocated_bytes(), 0);
    assert!(!norito::core::decode_limits_active());
    projection
}

#[test]
fn standalone_epoch_parse_keeps_exact_inline_projections_and_fresh_custody() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history();
    let mut peers = fixture.unavailable_peers();
    assert!(fixture.owner.authority.checkpoint_import_scope().is_none());
    let context =
        iroha_data_model::sumeragi_finality::authenticated_genesis(fixture.native.chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
    let original = {
        let mut cold = EpochValidationScope::new();
        epoch_projection(&mut cold, &context)
    };
    assert_eq!(
        original,
        iroha_data_model::sumeragi_finality::core_epoch(&context).unwrap()
    );

    // The unchanged shared parser really imports a cold checkpoint with this epoch workspace.
    // This retains no body, source, certificate or current signing decision in the workspace.
    cold_imports(&fixture.owner);
    let attempts = fixture.owner.authority.test_checkpoint_import_attempts();
    {
        let mut validation = EpochValidationScope::new();
        let parsed = BodyHistory::open_with_imports(
            &fixture.owner,
            CustodyPurpose::Renewal(2),
            &mut CheckpointImports::new(&fixture.owner.authority, Some(&mut validation)),
        )
        .unwrap()
        .unwrap();
        assert!(fixture.owner.authority.test_checkpoint_import_attempts() > attempts);
        assert_same(&parsed, &history);
        // Fixed inline snapshots consume no decoder allowance on either a miss or a hit.
        // Exact two-entry retention and revalidation after eviction are checked at the
        // native owner's epoch_scope_is_exact_owned_and_bounded_with_revalidation_after_eviction
        // test using its private validation count; allocation is no longer a cache-hit probe.
        assert_eq!(epoch_projection(&mut validation, &context), original);
        let mut second = context.clone();
        second.leader_seed[0] ^= 1;
        let second_core = iroha_data_model::sumeragi_finality::core_epoch(&second).unwrap();
        assert_ne!(second_core.id, original.id);
        let mut third = context.clone();
        third.leader_seed[0] ^= 2;
        let third_core = iroha_data_model::sumeragi_finality::core_epoch(&third).unwrap();
        assert_ne!(third_core.id, original.id);
        assert_ne!(third_core.id, second_core.id);
        assert_eq!(epoch_projection(&mut validation, &second), second_core);
        assert_eq!(epoch_projection(&mut validation, &context), original);
        assert_eq!(epoch_projection(&mut validation, &third), third_core);
        assert_eq!(epoch_projection(&mut validation, &second), second_core);
        assert_eq!(epoch_projection(&mut validation, &third), third_core);
        assert_eq!(epoch_projection(&mut validation, &context), original);
        let mut invalid = context.clone();
        invalid.leader_seed = [0; 32];
        let expected_error = iroha_data_model::sumeragi_finality::core_epoch(&invalid)
            .unwrap_err()
            .to_string();
        let invalid_budget = DecodeBudgetContext::new(limits(0));
        let actual_error = invalid_budget
            .with(|| validation.core_epoch(&invalid))
            .unwrap_err()
            .to_string();
        assert_eq!(actual_error, expected_error);
        assert_eq!(invalid_budget.consumed_allocated_bytes(), 0);
        assert!(!norito::core::decode_limits_active());
        assert_eq!(epoch_projection(&mut validation, &context), original);
    }
    assert_eq!(
        epoch_projection(&mut EpochValidationScope::new(), &context),
        original
    );

    assert_same(&standalone(&fixture.owner).unwrap(), &history);
    let retained = history.read_current(&fixture.owner).unwrap();
    assert_same(&retained, &history);
    assert!(Arc::ptr_eq(&retained.root, &history.root));
    drop(retained);
    // A successful earlier import grants no verdict for a later source read.
    let oldest = &history.bodies[0].directory;
    let original = oldest.read("reserved.nrt", MAX_BODY_BYTES).unwrap();
    oldest
        .write_atomic("reserved.nrt", &[0xff], PublishMode::Replace)
        .unwrap();
    let ordinary = error(independent(&fixture.owner));
    let actual = error(standalone(&fixture.owner));
    assert_eq!(actual, ordinary);
    error(history.read_current(&fixture.owner));
    oldest
        .write_atomic("reserved.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        oldest.read("reserved.nrt", MAX_BODY_BYTES).unwrap(),
        original
    );
    assert_same(&standalone(&fixture.owner).unwrap(), &history);
    assert_same(&history.read_current(&fixture.owner).unwrap(), &history);

    history
        .root
        .write_atomic(
            "unexpected.nrt",
            b"not an enrollment record",
            PublishMode::CreateNew,
        )
        .unwrap();
    let ordinary = error(independent(&fixture.owner));
    assert_eq!(error(standalone(&fixture.owner)), ordinary);
    error(history.read_current(&fixture.owner));
    std::fs::remove_file(history.root.path().join("unexpected.nrt")).unwrap();
    assert_same(&standalone(&fixture.owner).unwrap(), &history);
    assert_same(&history.read_current(&fixture.owner).unwrap(), &history);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let original = std::fs::metadata(history.root.path())
            .unwrap()
            .permissions();
        std::fs::set_permissions(history.root.path(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let ordinary = independent(&fixture.owner);
        let actual = standalone(&fixture.owner);
        let retained = history.read_current(&fixture.owner);
        std::fs::set_permissions(history.root.path(), original).unwrap();
        assert_eq!(error(actual), error(ordinary));
        error(retained);
        assert_same(&standalone(&fixture.owner).unwrap(), &history);
        assert_same(&history.read_current(&fixture.owner).unwrap(), &history);
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn standalone_epoch_parse_keeps_exact_active_charges_refusal_and_retry() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history();
    let mut peers = fixture.unavailable_peers();
    let warm = standalone(&fixture.owner).unwrap();
    assert_same(&warm, &history);
    assert_same(&history.read_current(&fixture.owner).unwrap(), &history);
    let ceiling = 512 * 1024 * 1024;
    let baseline = DecodeBudgetContext::new(limits(ceiling));
    let expected = baseline.with(|| independent(&fixture.owner)).unwrap();
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 1 && charge < ceiling as u64);
    let exact = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let actual = exact.with(|| standalone(&fixture.owner)).unwrap();
    assert_eq!(exact.consumed_allocated_bytes(), charge);
    assert_same(&actual, &expected);

    // Consuming reparses retain their original handle and full closing-prefix fences.
    let retained_baseline = DecodeBudgetContext::new(limits(ceiling));
    let expected = retained_baseline
        .with(|| history.read_current(&fixture.owner))
        .unwrap();
    let retained_charge = retained_baseline.consumed_allocated_bytes();
    assert!(retained_charge > 1 && retained_charge < ceiling as u64);
    let exact = DecodeBudgetContext::new(limits(usize::try_from(retained_charge).unwrap()));
    let actual = exact.with(|| history.read_current(&fixture.owner)).unwrap();
    assert_eq!(exact.consumed_allocated_bytes(), retained_charge);
    assert_same(&actual, &expected);
    assert!(Arc::ptr_eq(&actual.root, &history.root));

    for cap in [0, 1] {
        let baseline = DecodeBudgetContext::new(limits(cap));
        let original_error = error(baseline.with(|| independent(&fixture.owner)));
        let budget = DecodeBudgetContext::new(limits(cap));
        let actual_error = error(budget.with(|| standalone(&fixture.owner)));
        assert_eq!(actual_error, original_error);
        assert_eq!(
            budget.consumed_allocated_bytes(),
            baseline.consumed_allocated_bytes()
        );
        let retained = DecodeBudgetContext::new(limits(cap));
        error(retained.with(|| history.read_current(&fixture.owner)));
        assert!(!norito::core::decode_limits_active());
        assert_same(&standalone(&fixture.owner).unwrap(), &history);
        assert_same(&history.read_current(&fixture.owner).unwrap(), &history);
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
