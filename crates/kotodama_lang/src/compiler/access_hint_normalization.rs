//! Remove state hints already covered by the same authenticated wildcard.
//!
//! Publication keeps the exact state-wide conflict fence and every ledger key.
//! This only reduces redundant metadata; IR, executable words, value schemas,
//! dynamic scan hints and the original completeness reports remain unchanged.

use super::STATE_WILDCARD_KEY;

pub(super) fn canonical_state_hint_keys(mut keys: Vec<String>) -> Vec<String> {
    #[cfg(test)]
    if RETAIN_COVERED_STATE_KEYS.get() {
        return keys;
    }
    if keys.iter().any(|key| key == STATE_WILDCARD_KEY) {
        // The scheduler's state_claim_covers_key treats this authenticated
        // wildcard as covering every state key, including bounded map scans.
        // Keep unrelated namespaces and their original deterministic order.
        keys.retain(|key| key == STATE_WILDCARD_KEY || !key.starts_with("state:"));
    }
    keys
}

#[cfg(test)]
std::thread_local! {
    static RETAIN_COVERED_STATE_KEYS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Compare the same compiler with the prior redundant metadata publication.
#[cfg(test)]
fn with_covered_state_keys<R>(body: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            RETAIN_COVERED_STATE_KEYS.set(self.0);
        }
    }
    let _restore = Restore(RETAIN_COVERED_STATE_KEYS.replace(true));
    body()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::CompilerOptions,
        metadata::ProgramMetadata,
        session::{CompileOutput, CompileRequest, CompilerSession},
    };

    fn keys(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn state_wildcard_keeps_ledger_keys_order_and_original_coverage() {
        let before = keys(&[
            "state:counter",
            "account:$authority",
            "state:Rows[*]",
            "state:Rows/00",
            "state:*",
            "asset:exact",
            "*",
            "stateful:counter",
            "State:counter",
        ]);
        assert_eq!(
            canonical_state_hint_keys(before),
            keys(&[
                "account:$authority",
                "state:*",
                "asset:exact",
                "*",
                "stateful:counter",
                "State:counter",
            ])
        );
        // No same-class wildcard means no normalization, even if a global
        // wildcard or another namespace appears in this vector.
        for before in [
            Vec::new(),
            keys(&["state:counter", "state:Rows[*]", "state:Rows/00"]),
            keys(&["*", "state:counter", "account:*"]),
        ] {
            assert_eq!(canonical_state_hint_keys(before.clone()), before);
        }
    }

    #[test]
    fn conservative_comparison_scope_retires_after_unwind() {
        let before = keys(&["state:counter", "state:*"]);
        assert_eq!(
            with_covered_state_keys(|| canonical_state_hint_keys(before.clone())),
            before
        );
        let failure = std::panic::catch_unwind(|| {
            with_covered_state_keys(|| panic!("metadata comparison unwind"))
        });
        assert!(failure.is_err());
        assert_eq!(canonical_state_hint_keys(before), keys(&["state:*"]));
    }

    fn compile(source: &str, retain_covered_keys: bool) -> CompileOutput {
        crate::session::run_with_compiler_stack(|| {
            let build = || {
                CompilerSession::new(CompilerOptions::default())
                    .build(CompileRequest {
                        source,
                        source_name: Some("covered_state_hints.ko"),
                    })
                    .expect("canonical source, schema, IR and artifact construction")
            };
            if retain_covered_keys {
                with_covered_state_keys(build)
            } else {
                build()
            }
        })
        .expect("existing compiler worker")
    }

    fn assert_metadata_only_difference(before: &CompileOutput, after: &CompileOutput) {
        let before_parsed = ProgramMetadata::parse(&before.artifact).unwrap();
        let after_parsed = ProgramMetadata::parse(&after.artifact).unwrap();
        assert_eq!(
            &before.artifact[before_parsed.code_offset..],
            &after.artifact[after_parsed.code_offset..],
            "every executable word and relative function offset stays exact"
        );
        assert_eq!(
            &before.artifact[..before_parsed.header_len],
            &after.artifact[..after_parsed.header_len],
            "ABI, gas and mode header stays exact"
        );
        match (before_parsed.literal_section, after_parsed.literal_section) {
            (None, None) => {}
            (Some(before_section), Some(after_section)) => {
                assert_eq!(before_section.count, after_section.count);
                assert_eq!(
                    &before.artifact[before_section.entries_start..before_section.data_end],
                    &after.artifact[after_section.entries_start..after_section.data_end],
                    "literal descriptors and complete canonical payloads stay exact"
                );
            }
            _ => panic!("metadata normalization cannot add or remove literals"),
        }
        let mut expected = before.contract_interface.clone();
        for entrypoint in &mut expected.entrypoints {
            entrypoint.read_keys =
                canonical_state_hint_keys(std::mem::take(&mut entrypoint.read_keys));
            entrypoint.write_keys =
                canonical_state_hint_keys(std::mem::take(&mut entrypoint.write_keys));
        }
        if let Some(hints) = &mut expected.access_set_hints {
            hints.read_keys = canonical_state_hint_keys(std::mem::take(&mut hints.read_keys));
            hints.write_keys = canonical_state_hint_keys(std::mem::take(&mut hints.write_keys));
        }
        assert_eq!(
            expected, after.contract_interface,
            "all callable, argument/result, state, error, permission, trigger, ledger and completeness metadata stays exact"
        );
        assert_eq!(
            after_parsed.contract_interface.as_ref().unwrap(),
            &expected,
            "the complete parsed CNTR reproduces the published interface"
        );
        let mut expected_manifest = before.manifest.clone();
        expected_manifest.code_hash = after.manifest.code_hash;
        expected_manifest.access_set_hints = expected.access_set_hints.clone();
        expected_manifest.entrypoints = Some(
            expected
                .entrypoints
                .iter()
                .map(|entrypoint| entrypoint.to_manifest_descriptor())
                .collect(),
        );
        assert_eq!(expected_manifest, after.manifest);
        for output in [before, after] {
            assert_eq!(
                output.manifest.code_hash,
                Some(crate::metadata::contract_code_hash(&output.artifact))
            );
            assert_eq!(
                output.report.artifact_hash,
                crate::metadata::contract_code_hash(&output.artifact)
            );
        }
        assert_ne!(
            before.manifest.code_hash, after.manifest.code_hash,
            "changed metadata must produce a new complete artifact identity"
        );
        assert!(after.artifact.len() < before.artifact.len());
    }

    #[test]
    fn transitive_dynamic_paths_keep_exact_wildcard_and_original_completeness() {
        let source = r#"seiyaku CoveredStateHints { permission Entry;
            state int counter;
            state StateMap<int, int> values;
            hajimari() { counter = 0; }
            fn touch(int _ key) { counter = counter + 1; values[key] = counter; }
            kotoage fn update(int key) authorize(Entry) { touch(key); }
            view fn read(int key) authorize(anyone) -> int { return values.get(key).unwrap_or(counter); }
        }"#;
        let before = compile(source, true);
        let after = compile(source, false);
        assert_metadata_only_difference(&before, &after);
        for name in ["update", "read"] {
            let entrypoint = after
                .contract_interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == name)
                .unwrap();
            assert_eq!(entrypoint.read_keys, keys(&["state:*"]));
            assert_eq!(entrypoint.access_hints_complete, Some(false));
            assert_eq!(
                entrypoint.access_hints_skipped,
                keys(&[super::super::HINT_SKIP_DYNAMIC_STATE_PATH])
            );
            assert_eq!(
                entrypoint.write_keys,
                if name == "update" {
                    keys(&["state:*"])
                } else {
                    Vec::new()
                }
            );
        }
        assert_eq!(after.artifact, compile(source, false).artifact);
    }

    #[test]
    fn canonical_dlmm_hint_subsumption_measures_exact_metadata_savings() {
        let source = include_str!("../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
        let before = compile(source, true);
        let after = compile(source, false);
        assert_metadata_only_difference(&before, &after);
        let before_keys: usize = before
            .contract_interface
            .entrypoints
            .iter()
            .map(|entrypoint| entrypoint.read_keys.len() + entrypoint.write_keys.len())
            .sum();
        let after_keys: usize = after
            .contract_interface
            .entrypoints
            .iter()
            .map(|entrypoint| entrypoint.read_keys.len() + entrypoint.write_keys.len())
            .sum();
        assert!(after_keys < before_keys);
        eprintln!(
            "canonical DLMM covered state hints: baseline_bytes={} optimized_bytes={} saved_bytes={} baseline_entrypoint_keys={before_keys} optimized_entrypoint_keys={after_keys} baseline_hash={} optimized_hash={}",
            before.artifact.len(),
            after.artifact.len(),
            before.artifact.len() - after.artifact.len(),
            before.report.artifact_hash,
            after.report.artifact_hash
        );
        // Static savings alone do not qualify the default policy. The actual
        // unchanged Core payout and paid disposable-network gates remain.
    }
}
