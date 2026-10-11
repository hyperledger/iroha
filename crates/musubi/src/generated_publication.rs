//! Explicit generated publication through the existing command, wallet and registry owners.
//!
//! The deployment adapter validates the original generated profile before supplying its context.
//! This entry does not infer signing intent from namespace text or arbitrary workspace TOML.
use crate::{
    output::{CommandOutput, Diagnostic, ErrorCode},
    publication_runtime::GeneratedPublicationContextV1,
    publish::PublicationOperationIdV1,
};
use iroha_data_model::musubi::{MusubiNamespaceV1, MusubiPackageSelectorV1};
use std::path::{Path, PathBuf};

pub use crate::output::{OutputFormat, RenderedOutput};

/// One explicit generated publication action over the same ordinary durable publication engine.
#[derive(Clone, Debug)]
pub enum GeneratedPublishAction {
    /// Resolve/package and begin one publication; preflight binds a selected member to its package.
    /// With a workspace-root input, `None` preserves the root's default-member selection.
    Begin {
        /// Exact workspace selector, never an implicit namespace rewrite.
        package: Option<MusubiPackageSelectorV1>,
        /// Return at the existing durable seed-ingress boundary.
        detach: bool,
    },
    /// Continue one exact original journal without replacing its request or namespace authorization.
    Resume {
        /// Original immutable publication operation.
        operation_id: PublicationOperationIdV1,
    },
    /// Rebuild only a pristine original journal's missing package sidecars through the existing owner.
    Recover {
        /// Original immutable publication operation.
        operation_id: PublicationOperationIdV1,
    },
}
/// Validate local selection before publication opens or starts its managed environment.
///
/// A non-root member manifest selects only its owning package. A workspace-root input retains
/// ordinary default-member and explicit-package selection. Resume never opens source manifests;
/// Recover retains workspace validation and leaves its exact package selection to the journal.
/// This preflight grants no publication authority; the canonical engine reopens and validates
/// the selected workspace and its complete package graph before publication.
///
/// # Errors
/// Refuses invalid workspaces, a member input naming another package, or an ambiguous Begin.
pub fn prepare_generated_publish_action(
    manifest: &Path,
    mut action: GeneratedPublishAction,
) -> eyre::Result<GeneratedPublishAction> {
    if matches!(&action, GeneratedPublishAction::Resume { .. }) {
        return Ok(action);
    }
    let workspace = crate::workspace::load_workspace(manifest)?;
    if let GeneratedPublishAction::Begin { package, .. } = &mut action {
        let selected_manifest = crate::workspace::discover_manifest(manifest)?;
        if selected_manifest != workspace.root_manifest_path() {
            let member = workspace
                .members()
                .values()
                .find(|member| member.manifest_path == selected_manifest)
                .ok_or_else(|| eyre::eyre!("selected manifest has no owning workspace member"))?;
            eyre::ensure!(
                package
                    .as_ref()
                    .is_none_or(|package| package == &member.package.selector),
                "selected member manifest cannot select another package"
            );
            if package.is_none() {
                *package = Some(member.package.selector.clone());
            }
        }
        let packages = package.iter().cloned().collect::<Vec<_>>();
        eyre::ensure!(
            workspace.select_members(false, &packages, &[])?.len() == 1,
            "package publication requires exactly one selected member"
        );
    }
    Ok(action)
}
/// Exact workspace and client-owned publication journal selection; no credentials are copied here.
#[derive(Clone, Debug)]
pub struct GeneratedPublishRequest {
    /// Explicit package/workspace manifest.
    pub manifest_path: PathBuf,
    /// Explicit private publication engine root. Namespace custody always comes from original context.
    pub state_root: PathBuf,
    /// Explicit private resolver/archive cache root; no operating-system user cache is selected.
    pub cache_root: PathBuf,
    /// Exact retained generated account transport, including original TLS pins and native discovery.
    pub archive_transport: crate::archive_fetch::PreparedProductionSorafsArchiveTransportV1,
    /// Existing engine action to execute.
    pub action: GeneratedPublishAction,
}
/// Canonical command output without a second publication reporting format.
pub struct GeneratedPublishOutcome(CommandOutput);
impl GeneratedPublishOutcome {
    /// Return the existing stable command exit status.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.0.exit_code()
    }
    /// Render through the sole redacting human/JSON command owner.
    /// # Errors
    /// Returns the canonical output owner's Norito JSON serialization error.
    pub fn render(&self, format: OutputFormat) -> Result<RenderedOutput, norito::json::Error> {
        self.0.render(format)
    }
}
/// Publish with explicit original generated context; ordinary CLI selection remains unchanged.
///
/// The caller selects this effectful entry, including its original namespace fee intent. First use
/// uses the sole originally initialized wallet parent. Existing exact native binding permits a
/// read-only skip after complete custody validation. Actual publication remains the same engine.
#[must_use]
pub fn publish_generated(
    context: &GeneratedPublicationContextV1,
    request: &GeneratedPublishRequest,
) -> GeneratedPublishOutcome {
    GeneratedPublishOutcome(crate::command::publish_generated(context, request))
}

#[derive(Clone, Copy)]
pub(crate) struct Execution<'a> {
    pub(crate) context: &'a GeneratedPublicationContextV1,
    pub(crate) state_root: &'a Path,
    pub(crate) cache_root: &'a Path,
    pub(crate) archive_transport:
        &'a crate::archive_fetch::PreparedProductionSorafsArchiveTransportV1,
}
impl Execution<'_> {
    pub(crate) fn validate(&self) -> Result<(), Diagnostic> {
        if !self.state_root.is_absolute() || !self.cache_root.is_absolute() {
            return Err(refused());
        }
        let image = self.context.bound_image().map_err(|_| refused())?;
        let (config, _) =
            iroha::config::Config::load_bytes_with_musubi_publication(image.path(), image.bytes())
                .map_err(|_| refused())?;
        if self.archive_transport.network_id() != config.network_id
            || self.archive_transport.generated_local_registry_identity()
                != Some((config.chain.as_str(), &config.account))
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn validate_journal(
        &self,
        request: &crate::publish::PublicationRequestV1,
    ) -> Result<(), Diagnostic> {
        self.validate()?;
        let intent = self.context.namespace_intent();
        let transport = self.context.transport();
        let package = &request.publication.manifest.release.package;
        if request.network_id() != transport.network_id()
            || request.publisher != intent.publisher
            || request.namespace != intent.binding.namespace
            || package.home_dataspace != intent.binding.home_dataspace
            || package.scope != intent.binding.scope
            || request.expected_policy_revision != intent.policy.revision
            || request.seed_provider != transport.provider_id()
            || &request.ingress_broker != transport.provider_owner()
            || request.namespace_delegation.is_some()
        {
            return Err(refused());
        }
        // The full original binding (including generation) is retained in the initialized
        // namespace parent and checked again before the exact current-binding query.
        Ok(())
    }
    pub(crate) fn image(
        &self,
    ) -> Result<std::sync::Arc<crate::registry::RegistryPublicConfigImageV1>, Diagnostic> {
        self.validate()?;
        self.context
            .bound_image()
            .map(std::sync::Arc::new)
            .map_err(|_| refused())
    }
}
fn refused() -> Diagnostic {
    Diagnostic::new(ErrorCode::Publish, "generated namespace preflight refused or remains pending")
        .with_help("retry this explicit generated publish to observe the same original; missing or changed custody must not be recreated")
}

/// Current queries are transport observations from the canonical finalized registry route. Neither
/// these responses nor wallet node status substitutes for independent native ownership checks.
pub(crate) fn ensure_namespace(
    context: &GeneratedPublicationContextV1,
    namespace: &MusubiNamespaceV1,
    allow_first_use: bool,
) -> Result<(), Diagnostic> {
    use iroha::{
        blocking::AccountClient,
        client::{Client, musubi::QueryResult},
    };
    use iroha_data_model::musubi::{
        MusubiOrderedPrefixQueryV1, MusubiOrderedPrefixV1, MusubiPageRequestV1,
    };
    use iroha_wallet::operations::{AccountService, MusubiNamespaceBindingSelection};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let started = Instant::now();
    let deadline = started + Duration::from_secs(60);
    let deadline_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused())?
            .as_millis(),
    )
    .map_err(|_| refused())?
    .checked_add(60_000)
    .ok_or_else(refused)?;
    let intent = context.namespace_intent();
    if namespace != &intent.binding.namespace {
        return Err(refused());
    }
    let image = context.bound_image().map_err(|_| refused())?;
    let (config, _) =
        iroha::config::Config::load_bytes_with_musubi_publication(image.path(), image.bytes())
            .map_err(|_| refused())?;
    let selection = MusubiNamespaceBindingSelection {
        chain_id: config.chain.to_string(),
        network_id: config.network_id,
        owner: intent.publisher.clone(),
        binding: intent.binding.clone(),
        expected_policy_revision: intent.policy.revision,
    };
    let service = AccountService::new(config.clone()).map_err(|_| refused())?;
    // Open and census precede every HTTP call, even when exact current binding could skip a write.
    let parent = service
        .open_musubi_namespace_binding_parent(&intent.journal_root, &selection, &intent.fee_payment)
        .map_err(|_| refused())?;
    let client = Client::builder(config)
        .build()
        .map_err(|_| refused())?
        .with_request_deadline(deadline);
    let reader = AccountClient::from_client(client.account_client().map_err(|_| refused())?)
        .map_err(|_| refused())?;
    let query = MusubiOrderedPrefixQueryV1 {
        prefix: MusubiOrderedPrefixV1::new(&format!("{namespace}/")).map_err(|_| refused())?,
        page: MusubiPageRequestV1 {
            limit: 1,
            cursor: None,
        },
    };
    let current = || -> Result<bool, Diagnostic> {
        match reader
            .musubi()
            .ordered_prefix(&query)
            .map_err(|_| refused())?
        {
            QueryResult::Found(page) if page.namespace_binding == intent.binding => Ok(true),
            QueryResult::NotFound => Ok(false),
            QueryResult::Found(_) | QueryResult::StaleCursor => Err(refused()),
        }
    };
    if current()? {
        parent.inspect(deadline).map_err(|_| refused())?;
        return Ok(());
    }
    if !allow_first_use {
        return Err(refused());
    }
    parent
        .advance(deadline_unix_ms, deadline)
        .map_err(|_| refused())?;
    // A successful node status alone is insufficient; require the exact current typed binding.
    if !current()? {
        return Err(refused());
    }
    parent.inspect(deadline).map_err(|_| refused())?;
    Ok(())
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    fn fixture(root: &Path, hybrid: bool) -> eyre::Result<(PathBuf, PathBuf)> {
        let root = root.join(if hybrid { "hybrid" } else { "virtual" });
        std::fs::create_dir_all(root.join("app"))?;
        std::fs::create_dir(root.join("other"))?;
        let package = |name: &str| {
            format!(
                "[package]\nnamespace = \"dev.universal\"\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"1\"\nabi-version = 1\n[lib]\nexports = []\n"
            )
        };
        std::fs::write(
            root.join("Musubi.toml"),
            format!(
                "manifest-version = 1\n{}[workspace]\nmembers = [\"app\", \"other\"]\ndefault-members = [\"other\"]\n",
                if hybrid {
                    package("root")
                } else {
                    String::new()
                }
            ),
        )?;
        for name in ["app", "other"] {
            std::fs::write(
                root.join(name).join("Musubi.toml"),
                format!("manifest-version = 1\n{}", package(name)),
            )?;
        }
        Ok((root.clone(), root.join("app/Musubi.toml")))
    }

    fn begin(package: Option<&str>, detach: bool) -> GeneratedPublishAction {
        GeneratedPublishAction::Begin {
            package: package.map(|package| package.parse().unwrap()),
            detach,
        }
    }

    fn selected_packages(
        manifest: &Path,
        action: &GeneratedPublishAction,
        expected_detach: bool,
    ) -> eyre::Result<Vec<String>> {
        let GeneratedPublishAction::Begin { package, detach } = action else {
            panic!("Begin action");
        };
        assert_eq!(*detach, expected_detach);
        let workspace = crate::workspace::load_workspace(manifest)?;
        Ok(workspace
            .select_members(false, &package.iter().cloned().collect::<Vec<_>>(), &[])?
            .iter()
            .map(|member| member.package.selector.to_string())
            .collect())
    }

    #[test]
    fn generated_publish_member_preflight_binds_owner_and_preserves_workspace_root_selection()
    -> eyre::Result<()> {
        let temporary = tempfile::tempdir()?;
        for hybrid in [false, true] {
            let (root, member) = fixture(temporary.path(), hybrid)?;
            for input in [member.as_path(), member.parent().unwrap()] {
                for package in [None, Some("dev.universal/app")] {
                    let action = prepare_generated_publish_action(input, begin(package, true))?;
                    let GeneratedPublishAction::Begin { package, .. } = &action else {
                        unreachable!();
                    };
                    assert_eq!(package.as_ref().unwrap().to_string(), "dev.universal/app");
                    assert_eq!(
                        selected_packages(input, &action, true)?,
                        ["dev.universal/app"]
                    );
                }
            }
            let root_manifest = root.join("Musubi.toml");
            for input in [root.as_path(), root_manifest.as_path()] {
                let action = prepare_generated_publish_action(input, begin(None, false))?;
                assert!(matches!(
                    &action,
                    GeneratedPublishAction::Begin { package: None, .. }
                ));
                assert_eq!(
                    selected_packages(input, &action, false)?,
                    ["dev.universal/other"]
                );
                let action = prepare_generated_publish_action(
                    input,
                    begin(Some("dev.universal/app"), true),
                )?;
                assert_eq!(
                    selected_packages(input, &action, true)?,
                    ["dev.universal/app"]
                );
                if hybrid {
                    let action = prepare_generated_publish_action(
                        input,
                        begin(Some("dev.universal/root"), false),
                    )?;
                    assert_eq!(
                        selected_packages(input, &action, false)?,
                        ["dev.universal/root"]
                    );
                }
            }
            assert!(!root.join("Musubi.lock").exists());
            assert!(!root.join("target").exists());
        }
        Ok(())
    }

    #[test]
    fn generated_publish_member_preflight_refuses_another_package_and_retries_original()
    -> eyre::Result<()> {
        let temporary = tempfile::tempdir()?;
        let (root, member) = fixture(temporary.path(), false)?;
        let original = std::fs::read(&member)?;
        for input in [member.as_path(), member.parent().unwrap()] {
            let error =
                prepare_generated_publish_action(input, begin(Some("dev.universal/other"), false))
                    .unwrap_err();
            assert_eq!(
                error.to_string(),
                "selected member manifest cannot select another package"
            );
            assert_eq!(std::fs::read(&member)?, original);
            let action = prepare_generated_publish_action(input, begin(None, false))?;
            assert_eq!(
                selected_packages(input, &action, false)?,
                ["dev.universal/app"]
            );
            let action =
                prepare_generated_publish_action(input, begin(Some("dev.universal/app"), true))?;
            assert_eq!(
                selected_packages(input, &action, true)?,
                ["dev.universal/app"]
            );
        }
        assert!(!root.join("Musubi.lock").exists());
        assert!(!root.join("target").exists());
        assert!(!root.join("publication-state").exists());
        Ok(())
    }

    #[test]
    fn generated_publish_member_preflight_keeps_ambiguous_root_refusal_and_source_retry()
    -> eyre::Result<()> {
        let temporary = tempfile::tempdir()?;
        let (root, member) = fixture(temporary.path(), false)?;
        let root_manifest = root.join("Musubi.toml");
        let original = std::fs::read_to_string(&root_manifest)?;
        std::fs::write(
            &root_manifest,
            original.replace(
                "default-members = [\"other\"]",
                "default-members = [\"app\", \"other\"]",
            ),
        )?;
        let error =
            prepare_generated_publish_action(&root_manifest, begin(None, false)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "package publication requires exactly one selected member"
        );
        let action = prepare_generated_publish_action(&member, begin(None, false))?;
        assert_eq!(
            selected_packages(&member, &action, false)?,
            ["dev.universal/app"]
        );
        let action = prepare_generated_publish_action(
            &root_manifest,
            begin(Some("dev.universal/app"), false),
        )?;
        assert_eq!(
            selected_packages(&root_manifest, &action, false)?,
            ["dev.universal/app"]
        );
        assert!(
            prepare_generated_publish_action(
                &root_manifest,
                begin(Some("dev.universal/missing"), false)
            )
            .is_err()
        );
        std::fs::write(&root_manifest, &original)?;
        let action = prepare_generated_publish_action(&root_manifest, begin(None, false))?;
        assert_eq!(
            selected_packages(&root_manifest, &action, false)?,
            ["dev.universal/other"]
        );
        Ok(())
    }

    #[test]
    fn generated_publish_member_preflight_keeps_resume_source_independent_and_recover_validated()
    -> eyre::Result<()> {
        let temporary = tempfile::tempdir()?;
        let (root, member) = fixture(temporary.path(), false)?;
        let operation_id = "56".repeat(32).parse()?;
        let missing = root.join("missing/Musubi.toml");
        for input in [member.as_path(), missing.as_path()] {
            let action = prepare_generated_publish_action(
                input,
                GeneratedPublishAction::Resume { operation_id },
            )?;
            assert!(
                matches!(action, GeneratedPublishAction::Resume { operation_id: actual } if actual == operation_id)
            );
        }
        let action = prepare_generated_publish_action(
            &member,
            GeneratedPublishAction::Recover { operation_id },
        )?;
        assert!(
            matches!(action, GeneratedPublishAction::Recover { operation_id: actual } if actual == operation_id)
        );
        let original = std::fs::read(&member)?;
        std::fs::write(&member, "invalid changed manifest")?;
        assert!(
            prepare_generated_publish_action(
                &member,
                GeneratedPublishAction::Recover { operation_id }
            )
            .is_err()
        );
        assert!(prepare_generated_publish_action(&member, begin(None, false)).is_err());
        let action = prepare_generated_publish_action(
            &member,
            GeneratedPublishAction::Resume { operation_id },
        )?;
        assert!(
            matches!(action, GeneratedPublishAction::Resume { operation_id: actual } if actual == operation_id)
        );
        std::fs::write(&member, original)?;
        let action = prepare_generated_publish_action(
            &member,
            GeneratedPublishAction::Recover { operation_id },
        )?;
        assert!(
            matches!(action, GeneratedPublishAction::Recover { operation_id: actual } if actual == operation_id)
        );
        assert!(!root.join("Musubi.lock").exists());
        Ok(())
    }
}
