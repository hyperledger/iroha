// Actual CoreHost contract dispatch under a shared completed-cycle allowance.
mod shared_vm_cycle_budget_tests {
    //! Low-level real nested execution; source admission/State policy are owned separately.
    use super::*;
    use std::num::NonZeroU64;

    #[test]
    fn actual_nested_contract_runs_share_an_exact_allowance_across_parent_vms() {
        let authority = fixture_account("alice");
        let state = contract_test_state(&authority);
        let caller = install_contract(
            &state,
            &authority,
            r#"
seiyaku CycleCaller { view fn main() authorize(anyone) -> int { return 0; } }
"#,
            0,
        );
        let callee = install_contract(
            &state,
            &authority,
            r#"
seiyaku CycleCallee { view fn value() authorize(anyone) -> int { return 42; } }
"#,
            1,
        );
        let run = |budget: &ivm::VmCycleBudget| {
            dispatch_call_contract_syscall_with_cycle_budget(
                &state,
                &authority,
                &caller,
                &callee,
                "value",
                Json::new(()),
                1_000_000,
                Some(budget),
            )
        };
        let measured = ivm::VmCycleBudget::new(NonZeroU64::new(1_000_000).unwrap());
        let (result, parent, overlay, _) = run(&measured);
        result.unwrap();
        assert!(overlay.is_empty());
        assert!(measured.consumed() > parent.get_cycle_count());
        let exact = measured.consumed();
        let allowance = ivm::VmCycleBudget::new(NonZeroU64::new(exact * 2).unwrap());
        for expected in [exact, exact * 2] {
            let (result, parent, overlay, _) = run(&allowance);
            result.unwrap();
            assert!(overlay.is_empty());
            assert_eq!(
                render_nested_result(
                    &parent,
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::Int
                ),
                norito::json!("42")
            );
            assert_eq!(allowance.consumed(), expected);
        }
        assert_eq!(allowance.remaining(), 0);
        assert!(!allowance.exhausted());
        let (result, parent, overlay, target) = run(&allowance);
        assert_eq!(result, Err(ivm::VMError::ExceededMaxCycles));
        assert_eq!(parent.get_cycle_count(), 0);
        assert_eq!(parent.register(14), target);
        assert!(parent.call_result_word_count().is_err());
        assert!(overlay.is_empty());
        assert_eq!(allowance.consumed(), exact * 2);
        assert!(allowance.exhausted());
    }

    #[test]
    fn actual_nested_contract_failure_keeps_cycles_and_rolls_back_child_effects() {
        let authority = fixture_account("alice");
        let state = contract_test_state(&authority);
        let caller = install_contract(
            &state,
            &authority,
            r#"
seiyaku CycleCaller { view fn main() authorize(anyone) -> int { return 0; } }
"#,
            0,
        );
        let callee = install_contract(
            &state,
            &authority,
            r#"
seiyaku CycleFailure { permission AssetOps;
  error enum Failure { Refused = 1 }
  state int counter;
  hajimari() { counter = 0; }
  kotoage fn fail_after_write() authorize(AssetOps) -> int {
    counter = 9;
    require(false, Failure::Refused);
    return 0;
  }
}
"#,
            1,
        );
        grant_asset_ops_to_account(&state, &authority, caller.subject_id());
        let prologue_cycles = authenticated_test_probe_prologue().len() as u64;
        // Six additional moves restore r10..r15 from staged operands before A9.
        let completed_parent_cycles = prologue_cycles + (10..=15).count() as u64;
        let boundary_only_limit = completed_parent_cycles + 1;
        for limit in [1_000_000, boundary_only_limit] {
            let allowance = ivm::VmCycleBudget::new(NonZeroU64::new(limit).unwrap());
            let (result, parent, overlay, target) =
                dispatch_call_contract_syscall_with_cycle_budget(
                    &state,
                    &authority,
                    &caller,
                    &callee,
                    "fail_after_write",
                    Json::new(()),
                    1_000_000,
                    Some(&allowance),
                );
            let error = result.unwrap_err();
            if limit == boundary_only_limit {
                assert_eq!(error.as_unmetered(), &ivm::VMError::ExceededMaxCycles);
                assert_eq!(
                    allowance.consumed(),
                    completed_parent_cycles,
                    "after staging, the parent reservation leaves no child cycle available"
                );
                assert!(allowance.exhausted());
            } else {
                assert!(matches!(
                    error.as_unmetered(),
                    ivm::VMError::ContractAbort { code: 1, .. }
                ));
                assert!(allowance.consumed() > parent.get_cycle_count());
                assert!(!allowance.exhausted());
            }
            assert!(allowance.is_open());
            assert!(
                overlay.is_empty(),
                "nested writes roll back on either actual failure"
            );
            assert_eq!(
                parent.register(10),
                target,
                "failed child publishes no return value"
            );
            assert!(
                parent.remaining_gas() < 1_000_000,
                "actual boundary/child work remains charged"
            );
        }
    }
}
