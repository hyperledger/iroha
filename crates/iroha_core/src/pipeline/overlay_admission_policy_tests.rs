#[test]
fn analysis_refusals_keep_their_original_owner_in_overlay() {
    let budget = iroha_allocation::AllocationBudget::new(1);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    for metadata in [false, true] {
        for allocation in [true, false] {
            let original = if allocation {
                IvmError::AllocationDeferred(refusal.clone())
            } else {
                IvmError::ExecutionDeferred(ivm::error::ExecutionDeferral::AllocationUnavailable)
            };
            let expected_reason = original.execution_deferral().unwrap();
            let error = if metadata {
                ProgramAnalysisError::Metadata(original)
            } else {
                ProgramAnalysisError::Decode(original)
            };
            let mapped = map_program_analysis_error(error);
            assert!(matches!(mapped, OverlayBuildError::IvmLoad(_)));
            let retained = mapped.into_execution_deferral().unwrap();
            assert_eq!(retained.reason(), expected_reason);
            assert_eq!(
                retained.allocation_refusal(),
                allocation.then_some(&refusal)
            );
        }
    }
    let malformed =
        map_program_analysis_error(ProgramAnalysisError::Metadata(IvmError::InvalidMetadata));
    assert!(matches!(malformed, OverlayBuildError::IvmHeaderParse));
    assert!(matches!(
        malformed.into_execution_deferral(),
        Err(OverlayBuildError::IvmHeaderParse)
    ));
    drop(occupied);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn generic_preparation_preserves_original_pool_refusal_in_overlay() {
    use crate::smartcontracts::ivm::cache::PreparedContractCache;
    use iroha_allocation::{AllocationBudget, AllocationRefusal};

    let mut program = ivm::ProgramMetadata {
        max_cycles: 10_000,
        ..ivm::ProgramMetadata::default()
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let occupied = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    let mut cache = IvmCache::with_prepared_contract_cache(
        0,
        PreparedContractCache::with_execution_budget(0, budget.clone()),
    );
    let original = cache.summarize_executable(&program).unwrap_err();
    let expected = match &original {
        IvmError::AllocationDeferred(original) => original.clone(),
        _ => panic!("original allocation refusal"),
    };
    assert!(matches!(expected, AllocationRefusal::Capacity { .. }));
    let mapped = map_program_summary_error(original);
    assert!(matches!(mapped, OverlayBuildError::IvmLoad(_)));
    assert_eq!(
        mapped
            .into_execution_deferral()
            .unwrap()
            .allocation_refusal(),
        Some(&expected)
    );
    drop(occupied);
    assert!(cache.summarize_executable(&program).is_ok());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn checked_keypair_preserves_default_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
}
#[test]
fn pre_execution_cycle_ceiling_accepts_exact_bound() {
    let meta = ivm::ProgramMetadata {
        max_cycles: 42,
        ..ivm::ProgramMetadata::default()
    };
    enforce_pre_execution_policy(
        NonZeroU64::new(42).expect("test ceiling is non-zero"),
        &meta,
    )
    .expect("artifact at the configured ceiling should be admitted");
}
#[test]
fn header_policy_rejects_zero_cycle_limit() {
    let meta = ivm::ProgramMetadata {
        max_cycles: 0,
        ..ivm::ProgramMetadata::default()
    };
    assert!(matches!(
        validate_header_policy(&meta),
        Err(IvmAdmissionError::MissingMaxCycles)
    ));
}
#[test]
fn pre_execution_cycle_ceiling_rejects_over_bound() {
    let meta = ivm::ProgramMetadata {
        max_cycles: 43,
        ..ivm::ProgramMetadata::default()
    };
    let error = enforce_pre_execution_policy(
        NonZeroU64::new(42).expect("test ceiling is non-zero"),
        &meta,
    )
    .expect_err("artifact above the configured ceiling must fail closed");
    assert!(matches!(
        error,
        OverlayBuildError::HeaderPolicy(
            IvmAdmissionError::MaxCyclesExceedsUpperBound(info)
        ) if info.max_cycles == 43 && info.upper_bound == 42
    ));
}
#[test]
fn empty_overlay_is_noop() {
    let ovl = TxOverlay::default();
    assert!(ovl.is_empty());
}

#[test]
fn header_policy_rejects_retired_minor_before_other_policy_errors() {
    let retired = ivm::ProgramMetadata {
        version_minor: 0,
        mode: 0xff,
        vector_length: 255,
        max_cycles: 0,
        abi_version: 2,
        ..ivm::ProgramMetadata::default()
    };
    assert!(matches!(validate_header_policy(&retired),
        Err(IvmAdmissionError::UnsupportedVersion(info)) if info.major == 1 && info.minor == 0));
    let current = ivm::ProgramMetadata {
        max_cycles: 1,
        ..ivm::ProgramMetadata::default()
    };
    assert!(validate_header_policy(&current).is_ok());
}
