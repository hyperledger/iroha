//! Explicit generated publication handoff over the sole config and TLS owners.
//!
//! Callers authenticate the original generated profile before supplying this intent. This
//! value grants no current namespace ownership, registry admission or provider completion.

use super::*;
use crate::registry::RegistryPublicConfigImageV1;
use iroha_data_model::{
    account::AccountId,
    musubi::{MusubiNamespaceBindingV1, MusubiRegistryPolicyV1},
    transaction::{FeeChargeKind, FeePaymentIntent},
};
use iroha_musubi_service::GeneratedLocalPublicationTransportV1;
use std::path::PathBuf;

/// Public original namespace and fee intent selected by the generated profile owner.
#[derive(Clone)]
pub struct GeneratedPublicationNamespaceIntentV1 {
    /// Exact developer account; native execution independently establishes ownership.
    pub publisher: AccountId,
    /// Original structural namespace and ownership generation.
    pub binding: MusubiNamespaceBindingV1,
    /// Registry policy actually projected from the retained signed genesis.
    pub policy: MusubiRegistryPolicyV1,
    /// Explicit authority-paid ceiling for the namespace transaction alone.
    pub fee_payment: FeePaymentIntent,
    /// Original explicitly initialized publisher namespace custody, never repaired by publish.
    pub journal_root: PathBuf,
}
impl fmt::Debug for GeneratedPublicationNamespaceIntentV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedPublicationNamespaceIntentV1")
            .field("publisher", &self.publisher)
            .field("binding", &self.binding)
            .field("policy_revision", &self.policy.revision)
            .finish_non_exhaustive()
    }
}

/// One bounded original client image joined to explicit generated TLS and namespace intent.
/// Raw image bytes and their process-local provenance are never returned in diagnostics.
pub struct GeneratedPublicationContextV1 {
    image: RegistryPublicConfigImageV1,
    transport: GeneratedLocalPublicationTransportV1,
    namespace: GeneratedPublicationNamespaceIntentV1,
}
impl fmt::Debug for GeneratedPublicationContextV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedPublicationContextV1")
            .field("original_bound", &true)
            .finish_non_exhaustive()
    }
}
impl GeneratedPublicationContextV1 {
    /// Bind the exact physical client image to independently selected generated original intent.
    /// The deployment owner supplies these inputs after signed-profile and genesis validation.
    /// No environment override, raw HTTP client or alternate TLS verifier is accepted.
    /// # Errors
    /// Refuses changed image, network, chain, signer, policy, routes, fees or namespace selection.
    pub fn from_original_image(
        path: &Path,
        bytes: &[u8],
        transport: GeneratedLocalPublicationTransportV1,
        namespace: GeneratedPublicationNamespaceIntentV1,
    ) -> Result<Self, ProductionPublicationConfigurationErrorV1> {
        let fail = generated_invalid;
        if bytes.is_empty()
            || bytes.len() > usize::try_from(MAX_CLIENT_CONFIG_BYTES).map_err(|_| fail())?
            || !namespace.journal_root.is_absolute()
        {
            return Err(fail());
        }
        namespace.binding.validate().map_err(|_| fail())?;
        namespace.policy.validate().map_err(|_| fail())?;
        namespace.fee_payment.validate().map_err(|_| fail())?;
        let FeePaymentIntent::Authority(fee) = &namespace.fee_payment else {
            return Err(fail());
        };
        if fee.gas_limit.is_some()
            || fee.charge_limits.len() != 1
            || fee.charge_limits[0].kind != FeeChargeKind::Nexus
            || fee.charge_limits[0].max_amount == iroha_primitives::numeric::Quantity::from(0_u32)
        {
            return Err(fail());
        }
        let image = RegistryPublicConfigImageV1::load(Some(path)).map_err(|_| fail())?;
        if image.bytes() != bytes {
            return Err(changed());
        }
        let (signing, publication) = RegistrySigningClientV1::load_with_publication_config_bytes(
            image.path(),
            image.bytes(),
        )
        .map_err(|_| fail())?;
        let (config, _) =
            iroha::config::Config::load_bytes_with_musubi_publication(image.path(), image.bytes())
                .map_err(|_| fail())?;
        let parsed = parse_publication_config(image.path(), &signing, &publication)?;
        if config.network_id != transport.network_id()
            || config.chain.as_str() != transport.chain_id()
            || config.account != namespace.publisher
            || parsed.bindings.ingress_broker != *transport.provider_owner()
            || parsed.bindings.seed_provider != transport.provider_id()
            || parsed.bindings.expected_policy_revision != namespace.policy.revision
            || parsed.bindings.namespace_delegation.is_some()
        {
            return Err(fail());
        }
        validate_routes(&parsed, &transport)?;
        Ok(Self {
            image,
            transport,
            namespace,
        })
    }
    /// Borrow immutable original namespace intent, without current native authority.
    #[must_use]
    pub fn namespace_intent(&self) -> &GeneratedPublicationNamespaceIntentV1 {
        &self.namespace
    }
    /// Load the signer and generated service client from this still-exact original image.
    /// # Errors
    /// Refuses file replacement or changed signer, routing, policy and TLS selection.
    pub fn load_runtime<V: PublicationCleanPackageValidatorV1>(
        &self,
        validator: V,
    ) -> Result<LoadedProductionPublicationRuntimeV1<V>, ProductionPublicationConfigurationErrorV1>
    {
        load_bound_generated_publication_runtime_v1(&self.provenance(), self, validator)
    }
    pub(crate) fn bound_image(
        &self,
    ) -> Result<RegistryPublicConfigImageV1, ProductionPublicationConfigurationErrorV1> {
        let current =
            RegistryPublicConfigImageV1::load(Some(self.image.path())).map_err(|_| changed())?;
        if current.bytes() != self.image.bytes() {
            return Err(changed());
        }
        Ok(current)
    }
    pub(crate) fn transport(&self) -> &GeneratedLocalPublicationTransportV1 {
        &self.transport
    }
    pub(crate) fn provenance(&self) -> PlatformConfigProvenanceV1 {
        self.image.provenance()
    }
}
pub(super) fn validate_routes(
    parsed: &ParsedProductionPublicationConfigV1,
    transport: &GeneratedLocalPublicationTransportV1,
) -> Result<(), ProductionPublicationConfigurationErrorV1> {
    transport
        .validate_base_url(&parsed.seed_ingress_url)
        .map_err(|_| generated_invalid())?;
    transport
        .validate_base_url(&parsed.storage_coordinator_url)
        .map_err(|_| generated_invalid())?;
    if parsed.provider_gateways.len() != 3
        || !parsed
            .provider_gateways
            .contains_key(&transport.provider_id())
    {
        return Err(generated_invalid());
    }
    for endpoint in parsed.provider_gateways.values() {
        transport
            .validate_base_url(&endpoint.readback)
            .map_err(|_| generated_invalid())?;
        let url = &endpoint.attestation;
        if url.scheme() != "http" || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]")) {
            return Err(generated_invalid());
        }
    }
    Ok(())
}
pub(crate) fn load_bound_generated_publication_runtime_v1<V: PublicationCleanPackageValidatorV1>(
    provenance: &PlatformConfigProvenanceV1,
    context: &GeneratedPublicationContextV1,
    validator: V,
) -> Result<LoadedProductionPublicationRuntimeV1<V>, ProductionPublicationConfigurationErrorV1> {
    if provenance.path() != context.image.path() || !provenance.matches(context.image.bytes()) {
        return Err(changed());
    }
    let image = context.bound_image()?;
    load_production_publication_runtime_from_bytes_v1(
        image.path(),
        image.bytes(),
        Some(context.transport.clone()),
        validator,
    )
}
fn generated_invalid() -> ProductionPublicationConfigurationErrorV1 {
    ProductionPublicationConfigurationErrorV1::new("MUSUBI_GENERATED_PUBLICATION_ORIGINAL_INVALID")
}
fn changed() -> ProductionPublicationConfigurationErrorV1 {
    ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_CONFIG_CHANGED")
}

#[cfg(test)]
mod tests;
