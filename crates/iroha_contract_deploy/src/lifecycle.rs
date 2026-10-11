//! Artifact-derived initialization guidance, separate from deployment and live lifecycle evidence.

use iroha::data_model::smart_contract::manifest::EntryPointKind;
use ivm_artifact_admission::VerifiedContractArtifact;
use norito::derive::{JsonDeserialize, JsonSerialize};
use norito::json::Value;

/// One initialization parameter declared by the verified contract interface.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct LifecycleParameter {
    /// Canonical parameter name.
    pub name: String,
    /// Canonical interface type name.
    pub type_name: String,
}

/// A seiyaku's initialization hook as its verified artifact declares it.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct LifecycleHook {
    /// Canonical entrypoint selector from the embedded interface.
    pub name: String,
    /// Declared parameter names and canonical type names, in declaration order.
    pub params: Vec<LifecycleParameter>,
}

impl LifecycleHook {
    /// Return the artifact's initialization hook, when canonical admission succeeds and it declares one.
    #[must_use]
    pub fn from_artifact(artifact: &[u8]) -> Option<Self> {
        let verified = ivm_artifact_admission::verify_contract_artifact(artifact).ok()?;
        Self::from_verified(&verified)
    }

    /// Read the canonical hook from an already admitted immutable artifact without decoding it again.
    #[must_use]
    pub fn from_verified(verified: &VerifiedContractArtifact) -> Option<Self> {
        verified
            .contract_interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.kind == EntryPointKind::Hajimari)
            .map(|entrypoint| Self {
                name: entrypoint.name.clone(),
                params: entrypoint
                    .params
                    .iter()
                    .map(|param| LifecycleParameter {
                        name: param.name.clone(),
                        type_name: param.type_name.clone(),
                    })
                    .collect(),
            })
    }

    /// Named JSON argument placeholders for presentation, never submitted argument values.
    #[must_use]
    pub fn arguments_template(&self) -> String {
        let mut template = norito::json::Map::new();
        for parameter in &self.params {
            template.insert(
                parameter.name.clone(),
                Value::from(format!("<{}>", parameter.type_name)),
            );
        }
        norito::json::to_string(&Value::Object(template)).unwrap_or_else(|_| "{}".to_owned())
    }

    /// Describe deployment-only completion; retained operations require conditional wording.
    #[must_use]
    pub fn guidance(self, recovered: bool) -> DeploymentLifecycleGuidance {
        DeploymentLifecycleGuidance {
            hook: self,
            recovered,
        }
    }
}

/// Optional next-step information, never evidence that the hook is currently pending or complete.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct DeploymentLifecycleGuidance {
    /// Exact initialization selector and named parameter schema from the authenticated artifact.
    pub hook: LifecycleHook,
    /// True for any repeat or resume: the hook may have run after the earlier deployment.
    pub recovered: bool,
}

impl DeploymentLifecycleGuidance {
    /// Shared CLI and desktop wording without guessing argument values or invoking the hook.
    #[must_use]
    pub fn summary(&self) -> String {
        let parameters = self
            .hook
            .params
            .iter()
            .map(|parameter| format!("{}: {}", parameter.name, parameter.type_name))
            .collect::<Vec<_>>()
            .join(", ");
        let hook = format!("{}({parameters})", self.hook.name);
        if self.recovered {
            format!(
                "If initialization hook `{hook}` has not already succeeded, run it once before other calls or views. Its current state was not checked."
            )
        } else {
            format!(
                "Deployment did not run initialization hook `{hook}`. If it has not already succeeded, run it once before other calls or views."
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_preserves_canonical_hook_schema_and_only_describes_deployment() {
        for spelling in ["hajimari", "始まり"] {
            let source = format!(
                "seiyaku Counter {{ state int value; {spelling}(int start) {{ value = start; }} view fn current() authorize(anyone) -> int {{ return value; }} }}"
            );
            let artifact = kotodama_lang::compiler::Compiler::new()
                .compile_source(&source)
                .unwrap();
            let verified = ivm_artifact_admission::verify_contract_artifact(&artifact).unwrap();
            let hook = LifecycleHook::from_artifact(&artifact).unwrap();
            assert_eq!(Some(hook.clone()), LifecycleHook::from_verified(&verified));
            assert_eq!(hook.name, "hajimari");
            assert_eq!(
                hook.params,
                [LifecycleParameter {
                    name: "start".into(),
                    type_name: "int".into()
                }]
            );
            assert_eq!(hook.arguments_template(), r#"{"start":"<int>"}"#);
            let fresh = hook.clone().guidance(false);
            assert_eq!(
                fresh.summary(),
                "Deployment did not run initialization hook `hajimari(start: int)`. If it has not already succeeded, run it once before other calls or views."
            );
            let retained = hook.guidance(true);
            assert!(retained.summary().starts_with(
                "If initialization hook `hajimari(start: int)` has not already succeeded"
            ));
            assert!(
                retained
                    .summary()
                    .ends_with("Its current state was not checked.")
            );
            for guidance in [fresh, retained] {
                let value = norito::json::to_value(&guidance).unwrap();
                assert_eq!(
                    value["hook"]["params"],
                    norito::json!([
                        {"name": "start", "type_name": "int"}
                    ])
                );
                let json = norito::json::to_vec(&guidance).unwrap();
                assert_eq!(
                    norito::json::from_slice::<DeploymentLifecycleGuidance>(&json).unwrap(),
                    guidance
                );
            }
        }
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku Quote { view fn quote() authorize(anyone) -> int { return 30; } }",
            )
            .unwrap();
        assert_eq!(LifecycleHook::from_artifact(&artifact), None);
        assert_eq!(LifecycleHook::from_artifact(b"not an artifact"), None);
    }
}
