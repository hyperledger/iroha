//! Original selected-root deployment evidence, separate from historical parent inclusion.

use super::*;
use iroha_contract_deploy::{DeploymentLifecycleGuidance, DeploymentReceipt};
use iroha_data_model::{
    NetworkId, account::address::ChainDiscriminantGuard, block::consensus::SumeragiRootScope,
};
use iroha_fs::PrivateDirectory;

/// Immutable selected ledger on which the deployment service verified `Applied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ManagedDeploymentExecution {
    /// Exact child or global genesis identity, also retained in the original receipt.
    pub network_id: NetworkId,
    /// Root ownership authenticated before execution, independent of transaction-status scope.
    pub root_scope: SumeragiRootScope,
}

/// A bounded observation of the original private ledger's separate parent workflow.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ManagedParentObservation {
    /// This private root has no configured attachment; no parent receipt is implied.
    NotConfigured,
    /// Authenticated managed-worker status; any confirmed cursor remains historical evidence.
    Observed {
        /// Existing status, without inferring that it covers the deployment's local commit.
        status: ManagedAttachmentStatus,
    },
    /// Status could not be bound to the original generation; local `Applied` remains valid.
    Unavailable {
        /// Public bounded reason, containing no underlying custody or transport error text.
        reason: String,
    },
}

/// Historical parent observation bound to the original child and signed parent identities.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ManagedParentReport {
    /// Parent genesis identity from the child's authenticated immutable root scope.
    pub parent_network_id: NetworkId,
    /// Original child genesis identity; a subsequently selected generation cannot replace it.
    pub child_network_id: NetworkId,
    /// Independent workflow observation, never an inferred deployment-anchored flag.
    pub observation: ManagedParentObservation,
}

impl ManagedParentReport {
    /// Concise historical evidence without inferring inclusion of a later local operation.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.observation {
            ManagedParentObservation::NotConfigured => "Parent attachment is not configured".into(),
            ManagedParentObservation::Unavailable { .. } => {
                "Parent attachment observation is unavailable".into()
            }
            ManagedParentObservation::Observed { status } => match status.parent_confirmed {
                Some(confirmed) => format!(
                    "Historical parent receipt: child block #{} in parent block #{}",
                    confirmed.child.height, confirmed.parent_height
                ),
                None => {
                    let phase = if status.stage == ManagedAttachmentPhase::Attached {
                        "awaiting verified receipt"
                    } else {
                        status.stage.as_str()
                    };
                    format!("Parent attachment: {phase}; no verified parent receipt")
                }
            },
        }
    }
}

/// Verified deployment result with local execution and parent evidence kept distinct.
///
/// The canonical receipt is preserved verbatim. In particular, `receipt.commit.scope` is the
/// native transaction-status scope on the selected ledger, not proof of public-parent inclusion.
#[derive(Debug)]
pub struct ManagedDeploymentReport {
    /// Original store-local context name.
    pub context: String,
    /// Immutable root captured before deployment or journal recovery.
    pub execution: ManagedDeploymentExecution,
    /// Separate parent observation for private roots; global roots have none.
    pub parent: Option<ManagedParentReport>,
    /// Unmodified service-verified Applied and artifact-readback evidence.
    pub receipt: DeploymentReceipt,
    /// Original owner-private recovery journal.
    pub journal: PathBuf,
    /// Optional artifact-derived hook guidance, separate from the unmodified Applied receipt.
    pub lifecycle: Option<DeploymentLifecycleGuidance>,
}

impl ManagedDeploymentReport {
    /// Encode one public result using the exact receipt's account-address discriminant.
    ///
    /// # Errors
    /// Returns a canonical JSON encoding failure, without changing deployment evidence.
    pub fn to_json(&self) -> std::result::Result<norito::json::Value, norito::json::Error> {
        let _profile = ChainDiscriminantGuard::enter(self.receipt.chain_discriminant);
        norito::json::to_value(&norito::json!({
            "status": "applied",
            "context": (self.context),
            "execution": (self.execution),
            "parent": (self.parent),
            "receipt": (self.receipt),
            "journal": (self.journal),
            "lifecycle": (self.lifecycle),
        }))
    }

    /// Concise local-success wording shared by CLI and desktop presentation.
    #[must_use]
    pub fn execution_summary(&self) -> String {
        match self.execution.root_scope {
            SumeragiRootScope::Global => format!("Applied on localnet {}", self.context),
            SumeragiRootScope::Dataspace { .. } => {
                format!("Applied on private dataspace {}", self.context)
            }
        }
    }

    /// Concise historical parent evidence; no comparison of heights implies inclusion.
    #[must_use]
    pub fn parent_summary(&self) -> Option<String> {
        self.parent.as_ref().map(ManagedParentReport::summary)
    }
}

/// Opaque original-generation capture made before signing or dispatching a deployment.
///
/// Retained native directories prevent path substitution during observation. No parent HTTP
/// request, finality catch-up, wallet operation or worker activation is performed by this type.
pub struct ManagedDeploymentTarget {
    store_root: PathBuf,
    directory: PrivateDirectory,
    generation: PrivateDirectory,
    prepared: PreparedLocalnet,
    root_kind: RootKind,
    pub(super) execution: ManagedDeploymentExecution,
}

impl ManagedStore {
    /// Capture the exact validated generation selected for the forthcoming deployment.
    ///
    /// # Errors
    /// Missing/replaced generation, unsafe custody, malformed root or changed selected context.
    pub fn capture_deployment(&self, selected: &ManagedContext) -> Result<ManagedDeploymentTarget> {
        let directory = self.directory(&selected.name)?;
        let generation = directory.open_child(generation::DIRECTORY)?;
        let retained = generation::read(&directory)?;
        store::validate_prepared(
            &selected.name,
            directory.path(),
            &retained.prepared,
            &retained.root_kind,
        )?;
        generation.revalidate()?;
        if retained.prepared.context != *selected {
            return Err(Error::Invalid(
                "deployment selection changed before capture".into(),
            ));
        }
        let root_scope = match &retained.root_kind {
            RootKind::Global => SumeragiRootScope::Global,
            RootKind::Private { spec } => spec.scope(),
        };
        let network_id = selected.network_id.parse().map_err(|_| {
            Error::Invalid("deployment context has an invalid network identity".into())
        })?;
        Ok(ManagedDeploymentTarget {
            store_root: self.root().into(),
            directory,
            generation,
            prepared: retained.prepared,
            root_kind: retained.root_kind,
            execution: ManagedDeploymentExecution {
                network_id,
                root_scope,
            },
        })
    }
}

impl ManagedDeploymentTarget {
    pub(super) fn fee_asset(&self) -> Result<iroha_data_model::asset::AssetDefinitionId> {
        match &self.root_kind {
            RootKind::Global => Ok(crate::localnet::localnet_xor_asset_definition_id()),
            RootKind::Private { spec } => crate::localnet::private_fee_policy(spec)
                .map(|policy| policy.asset_definition_id)
                .map_err(|_| Error::Invalid("retained private fee policy is invalid".into())),
        }
    }
    /// Combine service-verified local success with a bounded independent parent observation.
    ///
    /// Parent failure or concurrent generation replacement produces `Unavailable`; it cannot
    /// overturn a receipt that matches the original pre-execution capture.
    ///
    /// # Errors
    /// The supplied service receipt belongs to a different original network, authority or scope.
    pub fn finish(
        &self,
        store: &ManagedStore,
        receipt: DeploymentReceipt,
        journal: PathBuf,
    ) -> Result<ManagedDeploymentReport> {
        self.finish_with(receipt, journal, || self.observe_parent(store))
    }

    fn finish_with(
        &self,
        receipt: DeploymentReceipt,
        journal: PathBuf,
        observe: impl FnOnce() -> Result<Option<ManagedAttachmentStatus>>,
    ) -> Result<ManagedDeploymentReport> {
        let selected = &self.prepared.context;
        let _profile = ChainDiscriminantGuard::enter(receipt.chain_discriminant);
        if receipt.network_id != self.execution.network_id
            || receipt.chain_id != selected.chain_id
            || receipt.authority.to_string() != selected.account_id
            || receipt.dataspace_id.as_u64() != selected.dataspace_id
            || receipt.contract_address.dataspace_id().ok() != Some(receipt.dataspace_id)
        {
            return Err(Error::Invalid(
                "deployment receipt differs from its original captured target".into(),
            ));
        }
        let parent = match self.execution.root_scope {
            SumeragiRootScope::Global => None,
            SumeragiRootScope::Dataspace { parent_network_id, .. } => Some(ManagedParentReport {
                parent_network_id,
                child_network_id: self.execution.network_id,
                observation: match observe() {
                    Ok(Some(status)) => ManagedParentObservation::Observed { status },
                    Ok(None) => ManagedParentObservation::NotConfigured,
                    Err(_) => ManagedParentObservation::Unavailable {
                        reason: "could not observe parent attachment for the original deployment generation".into(),
                    },
                },
            }),
        };
        Ok(ManagedDeploymentReport {
            context: selected.name.clone(),
            execution: self.execution,
            parent,
            receipt,
            journal,
            lifecycle: None,
        })
    }

    pub(super) fn revalidate_generation(&self, store: &ManagedStore) -> Result<()> {
        self.directory.revalidate()?;
        self.generation.revalidate()?;
        if store.root() != self.store_root {
            return Err(Error::Invalid(
                "deployment observation belongs to another store".into(),
            ));
        }
        let retained = generation::read(&self.directory)?;
        if retained.prepared != self.prepared || retained.root_kind != self.root_kind {
            return Err(Error::Invalid(
                "deployment generation changed during execution".into(),
            ));
        }
        Ok(())
    }

    fn observe_parent(&self, store: &ManagedStore) -> Result<Option<ManagedAttachmentStatus>> {
        self.revalidate_generation(store)?;
        let status = store.dataspace_status(&self.prepared.context.name)?;
        self.revalidate_generation(store)?;
        status
            .map(|status| {
                if status.local.context != self.prepared.context {
                    return Err(Error::Invalid(
                        "parent observation belongs to another child generation".into(),
                    ));
                }
                Ok(status.attachment)
            })
            .transpose()
    }

    pub(super) fn parent_report(&self, store: &ManagedStore) -> Option<ManagedParentReport> {
        match self.execution.root_scope {
            SumeragiRootScope::Global => None,
            SumeragiRootScope::Dataspace { parent_network_id, .. } => Some(ManagedParentReport {
                parent_network_id,
                child_network_id: self.execution.network_id,
                observation: match self.observe_parent(store) {
                    Ok(Some(status)) => ManagedParentObservation::Observed { status },
                    Ok(None) => ManagedParentObservation::NotConfigured,
                    Err(_) => ManagedParentObservation::Unavailable {
                        reason: "could not observe parent attachment for the original contract execution generation".into(),
                    },
                },
            }),
        }
    }
}

#[cfg(test)]
mod tests;
