//! Exact composition of existing Taira and threshold custody for disposable brokers.

use super::*;
use crate::{
    RuntimeProviderBrokerBackendRegistryV1, RuntimeProviderBrokerBackendsV1,
    external_software_signer::{
        RuntimeConsensusThresholdSignerBackendsV1, RuntimeConsensusThresholdSignerCredentialErrorV1,
    },
    soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1,
};

const THRESHOLD_SLOTS: &[IrohaRuntimeProviderSlotV1] =
    &[IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner];

fn threshold_import_error(
    error: &RuntimeConsensusThresholdSignerCredentialErrorV1,
) -> IrohaRuntimeProviderRegistryErrorV1 {
    match error {
        RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable
        | RuntimeConsensusThresholdSignerCredentialErrorV1::Session(_)
        | RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(_)
        | RuntimeConsensusThresholdSignerCredentialErrorV1::Output(_) => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        _ => IrohaRuntimeProviderRegistryErrorV1::BindingMismatch,
    }
}

pub(super) struct DisposableRuntimeProviderBrokerV1 {
    catalog: IrohaRuntimeProviderBindingsV1,
    thresholds: IrohaRuntimeProviderBindingsV1,
    threshold_backends: RuntimeConsensusThresholdSignerBackendsV1,
    signer: Option<Arc<dyn SoracloudRuntimeMutationSignerV1>>,
}

impl RuntimeProviderBrokerBackendRegistryV1 for DisposableRuntimeProviderBrokerV1 {
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<RuntimeProviderBrokerBackendsV1, IrohaRuntimeProviderRegistryErrorV1> {
        if bindings != &self.catalog {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        let mut backends = self.threshold_backends.resolve(&self.thresholds)?;
        if let Some(signer) = &self.signer {
            backends = backends.with_soracloud_runtime_mutation_signer(signer.clone());
        }
        Ok(backends)
    }
}

pub(super) fn load_with_signer(
    catalog: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    reader: &mut impl std::io::Read,
    load_signer: impl FnOnce() -> Result<
        Arc<dyn SoracloudRuntimeMutationSignerV1>,
        TairaRuntimeSignerErrorV1,
    >,
) -> Result<DisposableRuntimeProviderBrokerV1, IrohaRuntimeProviderRegistryErrorV1> {
    catalog.validate_credential_memory_policy_v1(policy)?;
    let mut requested_signer = None;
    for binding in catalog.iter() {
        if binding.slot() == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner {
            if requested_signer.replace(binding).is_some() {
                return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
            }
        } else if !THRESHOLD_SLOTS.contains(&binding.slot()) {
            return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
        }
    }
    let credential_budget =
        iroha_allocation::AllocationBudget::new(policy.credential_max_memory_bytes.get());
    let thresholds = catalog.select_slots(THRESHOLD_SLOTS);
    let threshold_backends =
        RuntimeConsensusThresholdSignerBackendsV1::load_from_launchd_credential_bundle_v1(
            &thresholds,
            reader,
            &credential_budget,
        )
        .map_err(|error| threshold_import_error(&error))?;
    let signer = requested_signer
        .map(|binding| {
            let exact = binding
                .soracloud_runtime_signer_binding()
                .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
            let provider = load_signer().map_err(|error| match error {
                TairaRuntimeSignerErrorV1::DescriptorUnavailable
                | TairaRuntimeSignerErrorV1::CredentialUnavailable
                | TairaRuntimeSignerErrorV1::CredentialDecode(_)
                | TairaRuntimeSignerErrorV1::CredentialSession(_) => {
                    IrohaRuntimeProviderRegistryErrorV1::Unavailable
                }
                _ => IrohaRuntimeProviderRegistryErrorV1::BindingMismatch,
            })?;
            qualify_soracloud_runtime_mutation_signer_v1(exact.clone(), provider)
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        })
        .transpose()?;
    Ok(DisposableRuntimeProviderBrokerV1 {
        catalog: catalog.clone(),
        thresholds,
        threshold_backends,
        signer,
    })
}

/// Load the exact disposable broker catalog from inherited runtime credentials.
///
/// Standard input carries the canonical threshold bundle, including an explicit
/// empty bundle when no threshold slot is requested. FD198 is consumed only for
/// the configured Soracloud signer, using the shipping Taira credential loader.
/// The parsed local policy must match the catalog before reading either handoff;
/// both platform threshold handoffs receive the one original policy pool. The
/// stock broker independently qualifies every returned backend before readiness.
/// TODO: Fund supervisor input, outer shared controls and Core custody-map nodes
/// before full memory qualification.
///
/// # Errors
///
/// Rejects differing local memory policy, unsupported slots, missing or
/// substituted credentials, and any mismatch between the exact catalog and the
/// loaded public provider qualifications.
#[cfg(feature = "test-network-disposable-broker")]
pub fn load_disposable_runtime_provider_broker_v1(
    catalog: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    reader: &mut impl std::io::Read,
) -> Result<Box<dyn RuntimeProviderBrokerBackendRegistryV1>, IrohaRuntimeProviderRegistryErrorV1> {
    let registry = load_with_signer(catalog, policy, reader, || {
        let signer = taira_runtime_signer(load_inherited_key_pair()?)?;
        Ok(Arc::new(signer))
    })?;
    Ok(Box::new(registry))
}

#[cfg(test)]
mod threshold_import_error_tests {
    use super::*;

    #[test]
    fn local_credential_failures_are_unavailable_and_bad_credentials_stay_mismatched() {
        assert_eq!(
            threshold_import_error(&RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable),
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        );
        assert_eq!(
            threshold_import_error(&RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected),
            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
        );
    }
}
