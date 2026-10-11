//! Fixed generated catalog signing; durable publication and live gateway reload have separate owners.

use super::*;
use sorafs_manifest::gateway_compliance::{
    GATEWAY_COMPLIANCE_ACK_VERSION_V1, GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
    GATEWAY_COMPLIANCE_CATALOG_VERSION_V1, GatewayComplianceAcknowledgementPayloadV1,
    GatewayComplianceAcknowledgementV1, GatewayComplianceCatalogApprovalV1,
    GatewayComplianceCatalogPayloadV1, GatewayComplianceCatalogV1, validate_catalog_transition,
};

/// Generated catalogs live for at most one day, within the original material interval.
pub(crate) const GENERATED_CATALOG_VALIDITY_SECONDS: u64 = 86_400;

// These operations expose no unvalidated output: the live ServiceAuthority performs complete
// original-profile and operation-lock validation before and after each successful call.
impl RetainedServiceProfile {
    /// Sign an empty-feed catalog using the fixed original governance quorum.
    ///
    /// The publisher must authenticate the actual promoted predecessor and retain the returned
    /// original before dispatch. This helper authenticates local signing intent only. It cannot
    /// acknowledge a gateway reload, promote a catalog or establish service readiness.
    pub(crate) fn sign_gateway_compliance_catalog(
        &self,
        provider: ProviderId,
        previous: Option<&GatewayComplianceCatalogV1>,
        now_seconds: u64,
    ) -> crate::managed::Result<GatewayComplianceCatalogV1> {
        let invalid = || Error::Invalid("invalid original generated compliance catalog".into());
        let manifest = &self.manifest;
        let plan = retained(manifest, provider).map_err(|_| invalid())?;
        if now_seconds < plan.issued_at_unix() || now_seconds >= plan.expires_at_unix() {
            return Err(invalid());
        }
        let (sequence, predecessor_digest) = match previous {
            Some(previous) => {
                // An expired predecessor can remain the actual chain head. Verify its exact
                // original signature interval, without treating it as currently eligible.
                validate_generated_catalog(previous, &plan).map_err(|_| invalid())?;
                if previous.payload.generated_at_unix > now_seconds {
                    return Err(invalid());
                }
                (
                    previous
                        .payload
                        .sequence
                        .checked_add(1)
                        .ok_or_else(invalid)?,
                    Some(previous.payload.catalog_digest().map_err(|_| invalid())?),
                )
            }
            None => (1, None),
        };
        let payload = GatewayComplianceCatalogPayloadV1 {
            version: GATEWAY_COMPLIANCE_CATALOG_VERSION_V1,
            sequence,
            predecessor_digest,
            policy_digest: plan
                .trust_policy()
                .canonical_digest()
                .map_err(|_| invalid())?,
            generated_at_unix: now_seconds,
            valid_until_unix: now_seconds
                .checked_add(GENERATED_CATALOG_VALIDITY_SECONDS)
                .ok_or_else(invalid)?
                .min(plan.expires_at_unix()),
            source_anchors: Vec::new(),
            baseline_rules: Vec::new(),
            appeal_overrides: Vec::new(),
            legal_safety_holds: Vec::new(),
            toggles: Vec::new(),
        };
        validate_generated_payload(&payload, &plan).map_err(|_| invalid())?;
        let digest = payload.signing_digest().map_err(|_| invalid())?;
        // Read fresh private key bytes under the same retained original runtime ancestry.
        let directory = self.runtime().open_child(DIRECTORY)?;
        let directory = open_provider_directory(&directory, manifest.provider(provider)?.slot)?;
        let mut approvals = Vec::with_capacity(2);
        for (filename, signer) in CATALOG_KEYS[..2]
            .iter()
            .zip(&plan.trust_policy().catalog_signers[..2])
        {
            let key = read_service_private_key(&directory, filename)?;
            if public32(key.public_key()).map_err(|_| invalid())? != signer.public_key {
                return Err(invalid());
            }
            let signature = iroha_crypto::Signature::try_new(key.private_key(), &digest)
                .map_err(|_| invalid())?;
            approvals.push(GatewayComplianceCatalogApprovalV1 {
                version: GATEWAY_COMPLIANCE_APPROVAL_VERSION_V1,
                signer_id: signer.signer_id.clone(),
                signature: signature.payload().try_into().map_err(|_| invalid())?,
            });
        }
        let catalog = GatewayComplianceCatalogV1 { payload, approvals };
        catalog
            .verify(plan.trust_policy(), now_seconds, 0)
            .map_err(|_| invalid())?;
        validate_catalog_transition(previous, &catalog).map_err(|_| invalid())?;
        encode(&catalog).map_err(|_| invalid())?;
        directory.revalidate()?;
        Ok(catalog)
    }

    /// Authenticate historical generated catalog intent against the complete original profile.
    /// This establishes neither current catalog freshness nor actual controller state.
    pub(crate) fn validate_generated_gateway_catalog(
        &self,
        provider: ProviderId,
        catalog: &GatewayComplianceCatalogV1,
    ) -> crate::managed::Result<()> {
        let invalid = || Error::Invalid("invalid retained generated compliance catalog".into());
        let manifest = &self.manifest;
        let plan = retained(manifest, provider).map_err(|_| invalid())?;
        validate_generated_catalog(catalog, &plan).map_err(|_| invalid())?;
        Ok(())
    }

    /// Sign only the exact fresh catalog observed loaded by the supervised original gateway.
    /// The observation has no public constructor or decoder and is not native serving authority.
    pub(crate) fn sign_observed_gateway_catalog(
        &self,
        provider: ProviderId,
        observation: &crate::managed::gateway_compliance::ObservedGatewayCatalog,
        catalog: &GatewayComplianceCatalogV1,
    ) -> crate::managed::Result<GatewayComplianceAcknowledgementV1> {
        let invalid = || Error::Invalid("invalid original gateway reload observation".into());
        let manifest = &self.manifest;
        let plan = retained(manifest, provider).map_err(|_| invalid())?;
        validate_generated_catalog(catalog, &plan).map_err(|_| invalid())?;
        let now = crate::managed::native_operation::now_ms()? / 1_000;
        if observation.network() != plan.network_id()
            || observation.policy()
                != plan
                    .trust_policy()
                    .canonical_digest()
                    .map_err(|_| invalid())?
            || observation.catalog() != catalog.payload.catalog_digest().map_err(|_| invalid())?
            || !observation.is_fresh_at(now)
            || observation.observed_at() < catalog.payload.generated_at_unix
            || observation.observed_at() >= catalog.payload.valid_until_unix
        {
            return Err(invalid());
        }
        catalog
            .verify(plan.trust_policy(), now, 0)
            .map_err(|_| invalid())?;
        // Read fresh private key bytes under the same retained original runtime ancestry.
        let directory = self.runtime().open_child(DIRECTORY)?;
        let directory = open_provider_directory(&directory, manifest.provider(provider)?.slot)?;
        let key = read_service_private_key(&directory, ACK_KEYS[0])?;
        let signer = plan
            .trust_policy()
            .gateway_signers
            .first()
            .ok_or_else(invalid)?;
        if signer.signer_id != plan.gateway_label()
            || public32(key.public_key()).map_err(|_| invalid())? != signer.public_key
        {
            return Err(invalid());
        }
        let payload = GatewayComplianceAcknowledgementPayloadV1 {
            version: GATEWAY_COMPLIANCE_ACK_VERSION_V1,
            gateway_id: plan.gateway_label().to_owned(),
            catalog_digest: observation.catalog(),
            observed_at_unix: observation.observed_at(),
            accepted: true,
            rejection_code: None,
        };
        let signature = iroha_crypto::Signature::try_new(
            key.private_key(),
            &payload.signing_digest().map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        let acknowledgement = GatewayComplianceAcknowledgementV1 {
            payload,
            signature: signature.payload().try_into().map_err(|_| invalid())?,
        };
        acknowledgement
            .verify(
                plan.trust_policy(),
                observation.catalog(),
                observation.observed_at(),
                0,
            )
            .map_err(|_| invalid())?;
        encode(&acknowledgement).map_err(|_| invalid())?;
        directory.revalidate()?;
        Ok(acknowledgement)
    }
}

fn validate_generated_catalog(
    catalog: &GatewayComplianceCatalogV1,
    plan: &RetainedGatewayCompliancePlan,
) -> Result<()> {
    encode(catalog)?;
    validate_generated_payload(&catalog.payload, plan)?;
    ensure!(
        catalog.approvals.len() == 2
            && catalog
                .approvals
                .iter()
                .zip(&plan.trust_policy().catalog_signers[..2])
                .all(|(approval, signer)| approval.signer_id == signer.signer_id),
        "generated catalog differs from its original fixed governance quorum"
    );
    catalog.verify(plan.trust_policy(), catalog.payload.generated_at_unix, 0)?;
    Ok(())
}

fn validate_generated_payload(
    payload: &GatewayComplianceCatalogPayloadV1,
    plan: &RetainedGatewayCompliancePlan,
) -> Result<()> {
    ensure!(
        payload.generated_at_unix >= plan.issued_at_unix()
            && payload.valid_until_unix <= plan.expires_at_unix()
            && payload
                .valid_until_unix
                .checked_sub(payload.generated_at_unix)
                .is_some_and(
                    |duration| duration > 0 && duration <= GENERATED_CATALOG_VALIDITY_SECONDS
                )
            && payload.source_anchors.is_empty()
            && payload.baseline_rules.is_empty()
            && payload.appeal_overrides.is_empty()
            && payload.legal_safety_holds.is_empty()
            && payload.toggles.is_empty(),
        "generated catalog differs from its original empty-feed policy"
    );
    payload.validate()?;
    Ok(())
}

#[cfg(test)]
mod tests;
