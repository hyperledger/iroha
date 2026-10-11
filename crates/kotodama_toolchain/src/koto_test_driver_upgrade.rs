//! Fixture transitions from captured prior artifacts to the suite's current runtime code.

use super::*;

impl KotoTestHost {
    /// Stage one actual in-place replacement after the fixture seeded its prior storage.
    pub(super) fn upgrade_fixture_from(
        &mut self,
        previous: &ivm::PreparedContract,
    ) -> Result<(), String> {
        if self.fixture_upgrade_staged {
            return Err("a fixture may stage only one `upgrade_from` transition".into());
        }
        let current = self
            .program
            .as_ref()
            .ok_or_else(|| "`upgrade_from` requires a seiyaku runtime target".to_owned())?;
        if current.code_hash() == previous.code_hash() {
            return Err(
                "`upgrade_from` must name different prior code; identical code is not an upgrade"
                    .into(),
            );
        }
        ivm_abi::upgrade::validate_contract_upgrade(
            previous.contract_interface(),
            current.contract_interface(),
        )
        .map_err(|error| error.to_string())?;
        let current_artifact = current.artifact().to_vec();
        let owner = self.inner.caller_subject();
        let mut lifecycle =
            iroha_data_model::smart_contract::ContractLifecycleControlV1::direct(owner.clone());
        lifecycle.active_code_hash = Some(previous.code_hash());
        lifecycle.retained_code_hash = Some(previous.code_hash());
        let expected_revision = lifecycle.revision;
        let checkpoint = self.inner.checkpoint().ok_or_else(|| {
            "fixture host cannot retain the prior transition checkpoint".to_owned()
        })?;
        let transition = (|| {
            // This explicit fixture describes a completed historical instance. Every old scalar
            // must actually exist with its canonical value schema before replacement is allowed.
            self.inner.install_contract_fixture(
                self.contract_address.clone(),
                previous.artifact().to_vec(),
                lifecycle,
                None,
            )?;
            self.inner.replace_contract_fixture(
                &self.contract_address,
                current_artifact,
                &owner,
                expected_revision,
            )
        })();
        let pending = match transition {
            Ok(pending) => pending,
            Err(error) => {
                self.inner
                    .restore(checkpoint.as_ref())
                    .map_err(|restore| restore.to_string())?;
                return Err(format!(
                    "prior instance cannot be replaced: {error}; seed every prior scalar with canonical `state_set` values before `upgrade_from`"
                ));
            }
        };
        self.lifecycle = match pending {
            Some(EntryPointKind::Kaizen) => Lifecycle::PendingKaizen,
            None => Lifecycle::Active,
            Some(_) => return Err("replacement produced an invalid lifecycle transition".into()),
        };
        self.fixture_upgrade_staged = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotodama_lang::linker::SourceContractArtifact;

    const PREVIOUS: &str = r#"seiyaku Migration {
        state bool existing;
        hajimari() { existing = true; }
        view fn old() authorize(anyone) -> bool { existing }
    }"#;
    const CURRENT: &str = r#"seiyaku Migration {
        error enum Reason { Retry = 1 }
        state bool existing;
        state bool added;
        hajimari() { existing = true; added = false; }
        kaizen(bool fail, bool trap) -> Result<(), Reason> {
            existing = false;
            added = true;
            require(!trap, Reason::Retry);
            if fail { return Result::err(Reason::Retry); }
            Result::ok(())
        }
        view fn current() authorize(anyone) -> (bool, bool) { (existing, added) }
        fixture migration {
            state_set("existing", true);
            upgrade_from("prior.to");
            actor("app");
            grant_seiyaku_lifecycle_permission("app", "kaizen");
        }
        #[test(fixture = "migration")]
        fn returned_error_preserves_pending_migration_and_retry() {
            test::expect_any_reject_as(actor: "app", kotoage: "current", arguments: {});
            let result = test::invoke_kotoage_as(actor: "app", kotoage: "kaizen", arguments: { fail: true, trap: false });
            match result {
                Result::err(reason) => { test::assert_eq(actual: reason, expected: Reason::Retry); },
                Result::ok(_) => { test::assert(false); }
            }
            test::assert(existing);
            test::expect_any_reject_as(actor: "app", kotoage: "current", arguments: {});
            let completed = test::invoke_kotoage_as(actor: "app", kotoage: "kaizen", arguments: { fail: false, trap: false });
            match completed {
                Result::ok(_) => {},
                Result::err(_) => { test::assert(false); }
            }
            let current_state = test::invoke_kotoage(kotoage: "current", arguments: {});
            test::assert_eq(actual: current_state, expected: (false, true));
            test::expect_any_reject_as(actor: "app", kotoage: "kaizen", arguments: { fail: false, trap: false });
        }
        #[test(fixture = "migration")]
        fn rejected_migration_preserves_pending_and_storage() {
            test::expect_any_reject_as(actor: "app", kotoage: "kaizen", arguments: { fail: false, trap: true });
            test::assert(existing);
            test::expect_any_reject_as(actor: "app", kotoage: "current", arguments: {});
            let completed = test::invoke_kotoage_as(actor: "app", kotoage: "kaizen", arguments: { fail: false, trap: false });
            match completed {
                Result::ok(_) => {},
                Result::err(_) => { test::assert(false); }
            }
            test::assert_eq(actual: test::invoke_kotoage(kotoage: "current", arguments: {}), expected: (false, true));
        }
    }"#;

    fn run(current: &str, previous: Option<&str>) -> KotoTestRunReportV1 {
        let root = SourceModuleUnit {
            source_name: "contracts/current.ko".into(),
            source: current.into(),
        };
        let artifacts = previous
            .into_iter()
            .map(|source| SourceContractArtifact {
                source_name: "contracts/prior.to".into(),
                artifact: kotodama_lang::compiler::Compiler::new()
                    .compile_source(source)
                    .expect("compile prior artifact"),
            })
            .collect();
        run_tests_structured_source_with_modules_v1(
            &KotoTestRunRequestV1::new(&root.source_name, 753),
            &root,
            &KotoTestModuleGraphV1 {
                artifacts,
                ..Default::default()
            },
        )
        .expect("compile and run captured migration suite")
    }

    #[test]
    fn captured_prior_artifact_runs_actual_kaizen_and_keeps_failed_transition_pending() {
        let report = run(CURRENT, Some(PREVIOUS));
        assert_eq!(report.cases.len(), 2);
        assert!(report.is_success(), "{report:#?}");
    }

    #[test]
    fn upgrade_fixtures_reject_incompatible_and_uninitialized_prior_state() {
        for (prior, current, expected) in [
            (
                PREVIOUS
                    .replace("state bool existing", "state int existing")
                    .replace("existing = true", "existing = 1")
                    .replace("-> bool", "-> int"),
                CURRENT.to_owned(),
                "changes the complete durable type",
            ),
            (
                PREVIOUS.to_owned(),
                CURRENT.replace("state_set(\"existing\", true);", ""),
                "seed every prior scalar",
            ),
            (
                PREVIOUS.to_owned(),
                CURRENT.replace(
                    "state_set(\"existing\", true);",
                    "state_set(\"existing\", 1);",
                ),
                "seed every prior scalar",
            ),
            (
                PREVIOUS.to_owned(),
                CURRENT.replace(
                    "upgrade_from(\"prior.to\");",
                    "upgrade_from(\"prior.to\"); upgrade_from(\"prior.to\");",
                ),
                "only one `upgrade_from`",
            ),
        ] {
            let report = run(&current, Some(&prior));
            assert_eq!(report.failed(), 2, "{report:#?}");
            assert!(
                report.cases.iter().all(|case| case
                    .failure
                    .as_deref()
                    .is_some_and(|failure| failure.contains(expected))),
                "{report:#?}"
            );
        }
    }

    #[test]
    fn upgrade_fixture_never_reopens_an_absent_inventory_path() {
        let report = run(CURRENT, None);
        assert_eq!(report.failed(), 2);
        assert!(
            report
                .cases
                .iter()
                .all(|case| case.failure.as_deref().is_some_and(
                    |failure| failure.contains("absent from the captured suite inventory")
                )),
            "{report:#?}"
        );
    }
}
