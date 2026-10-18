//! Canonical Torii routes for atomic private cross-dataspace settlement.
//!
//! These descriptors expose only bounded encrypted uploads, governed-auditor
//! capabilities, and redacted public status/receipt views. Runtime activation
//! and policy/key-epoch checks remain handler responsibilities.

use super::{
    AdmissionPolicy, ApiSurface, AuthenticationPolicy, FeatureGate, HttpMethod, Listener,
    RouteDescriptor, RouteEffect, RouteProjections,
};

const fn account_get(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Get,
        path,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_private_no_store()
    .with_cors_options(true)
}

const fn account_post(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Post,
        path,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_private_no_store()
    .with_cors_options(true)
}

const fn auditor_read_post(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Post,
        path,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::GovernedAuditor,
    )
    .with_authentication(AuthenticationPolicy::IdentityBoundSignature)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_private_no_store()
}

const fn validator_get(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Get,
        path,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::ValidatorRosterMember,
    )
    .with_authentication(AuthenticationPolicy::IdentityBoundSignature)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_private_no_store()
}

const fn auditor_post(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Post,
        path,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::GovernedAuditor,
    )
    .with_authentication(AuthenticationPolicy::IdentityBoundSignature)
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_private_no_store()
}

const fn public_get(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Get,
        path,
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_feature_gate(FeatureGate::Feature("app_api"))
    .with_projections(RouteProjections::OPENAPI_AND_SDK)
    .with_cors_options(true)
}

const fn test_network_diagnostic_get(id: &'static str, path: &'static str) -> RouteDescriptor {
    RouteDescriptor::new(
        id,
        HttpMethod::Get,
        path,
        ApiSurface::Diagnostic,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::ValidatorRosterMember,
    )
    .with_authentication(AuthenticationPolicy::IdentityBoundSignature)
    .with_feature_gate(FeatureGate::Feature(
        "test-network-private-settlement-route-control",
    ))
    .with_projections(RouteProjections::NONE)
    .with_private_no_store()
}

/// Authenticate public pool, native assignment and key originals at the requested current cut.
pub const CONTEXT: RouteDescriptor = RouteDescriptor::new(
    "private_settlement.context",
    HttpMethod::Post,
    "/v1/nexus/private-settlements/context/{height}",
    ApiSurface::Public,
    Listener::Torii,
    RouteEffect::ReadOnly,
    AdmissionPolicy::AuthenticatedAccount,
)
.with_authentication(AuthenticationPolicy::CanonicalAccountSignature)
.with_feature_gate(FeatureGate::Feature("app_api"))
.with_projections(RouteProjections::OPENAPI_AND_SDK)
.with_private_no_store()
.with_cors_options(true);

/// Upload one complete encrypted leg through restricted confidential DA.
pub const LEG_UPLOAD: RouteDescriptor = account_post(
    "private_settlement.leg.upload",
    "/v1/nexus/private-settlements/legs",
);
/// Persist provisional encrypted material and obtain this node's committee share.
pub const AVAILABILITY_SHARE: RouteDescriptor = account_post(
    "private_settlement.availability.share",
    "/v1/nexus/private-settlements/legs/availability-shares",
);
/// Independently verify, durably stage, and issue one participant Prepare vote.
pub const PREPARE_VOTE: RouteDescriptor = account_post(
    "private_settlement.phase.prepare_vote",
    "/v1/nexus/private-settlements/phases/prepare-votes",
);
/// Verify the exact complete Prepare barrier and issue one participant Commit vote.
pub const COMMIT_VOTE: RouteDescriptor = account_post(
    "private_settlement.phase.commit_vote",
    "/v1/nexus/private-settlements/phases/commit-votes",
);
/// Persist one exact aggregate Prepare or Commit certificate on a signer node.
pub const PHASE_CERTIFICATE: RouteDescriptor = account_post(
    "private_settlement.phase.certificate",
    "/v1/nexus/private-settlements/phases/certificates",
);
/// Recover exact locally durable Prepare and Commit certificates as the sponsor.
pub const PHASE_CERTIFICATES_GET: RouteDescriptor = account_get(
    "private_settlement.phase.certificates_get",
    "/v1/nexus/private-settlements/legs/{payload_digest}/phase-certificates",
);
/// Read redacted lifecycle information for an uploaded leg.
pub const LEG_STATUS: RouteDescriptor = account_get(
    "private_settlement.leg.status",
    "/v1/nexus/private-settlements/legs/{payload_digest}/status",
);
/// Fetch proof and approval material as an exact participant committee validator.
pub const COMMITTEE_PROOF: RouteDescriptor = validator_get(
    "private_settlement.committee.proof",
    "/v1/nexus/private-settlements/legs/{payload_digest}/committee-proof",
);
/// Fetch one padded encrypted audit capsule as an authorized local auditor.
pub const AUDITOR_CAPSULE: RouteDescriptor = auditor_read_post(
    "private_settlement.auditor.capsule",
    "/v1/nexus/private-settlements/legs/{payload_digest}/audit-capsule",
);
/// Submit a purpose-separated local-auditor approval for one leg.
pub const AUDITOR_APPROVAL: RouteDescriptor = auditor_post(
    "private_settlement.auditor.approval",
    "/v1/nexus/private-settlements/legs/{payload_digest}/audit-approvals",
);
/// Submit a complete Prepare-lock registration, finalization, or abort carrier
/// as its public sponsor.
pub const BUNDLE_SUBMIT: RouteDescriptor = account_post(
    "private_settlement.bundle.submit",
    "/v1/nexus/private-settlements/bundles",
);
/// Read allowlisted public lifecycle information for one bundle.
pub const BUNDLE_STATUS: RouteDescriptor = public_get(
    "private_settlement.bundle.status",
    "/v1/nexus/private-settlements/bundles/{bundle_id}",
);
/// Read the finalized public receipt or terminal abort marker for one bundle.
pub const BUNDLE_RECEIPT: RouteDescriptor = public_get(
    "private_settlement.bundle.receipt",
    "/v1/nexus/private-settlements/bundles/{bundle_id}/receipt",
);
/// Read a domain-separated state commitment on an explicitly instrumented
/// test-network validator.
///
/// This descriptor has no generated projection and cannot be mounted by a
/// shipping/default feature graph.
pub const TEST_NETWORK_STATE_COMMITMENT: RouteDescriptor = test_network_diagnostic_get(
    "private_settlement.test_network.state_commitment",
    "/v1/nexus/private-settlements/test-network/state-commitment",
);

/// Complete atomic-private-settlement Torii route family.
pub const ROUTES: &[RouteDescriptor] = &[
    CONTEXT,
    AVAILABILITY_SHARE,
    PREPARE_VOTE,
    COMMIT_VOTE,
    PHASE_CERTIFICATE,
    PHASE_CERTIFICATES_GET,
    LEG_UPLOAD,
    LEG_STATUS,
    COMMITTEE_PROOF,
    AUDITOR_CAPSULE,
    AUDITOR_APPROVAL,
    BUNDLE_SUBMIT,
    BUNDLE_STATUS,
    BUNDLE_RECEIPT,
    TEST_NETWORK_STATE_COMMITMENT,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_catalog::{CatalogProjection, EnabledFeatures, RouteCatalog};

    #[test]
    fn route_family_is_valid_and_sdk_projected() {
        let catalog = RouteCatalog::new(ROUTES);
        assert_eq!(catalog.validate(), Ok(()));
        assert_eq!(
            catalog
                .project(
                    CatalogProjection::Mounted,
                    EnabledFeatures::new(&["app_api"]),
                )
                .len(),
            ROUTES.len() - 1
        );
        assert_eq!(
            catalog
                .project(CatalogProjection::Sdk, EnabledFeatures::none())
                .len(),
            ROUTES.len() - 1
        );
        assert_eq!(
            TEST_NETWORK_STATE_COMMITMENT.projections(),
            RouteProjections::NONE
        );
        assert!(TEST_NETWORK_STATE_COMMITMENT.requires_private_no_store());
        assert_eq!(
            catalog
                .project(
                    CatalogProjection::Mounted,
                    EnabledFeatures::new(&[
                        "app_api",
                        "test-network-private-settlement-route-control",
                    ]),
                )
                .len(),
            ROUTES.len()
        );
    }

    #[test]
    fn restricted_routes_require_exact_principals_and_no_store() {
        for route in [
            CONTEXT,
            AVAILABILITY_SHARE,
            PREPARE_VOTE,
            COMMIT_VOTE,
            PHASE_CERTIFICATE,
            PHASE_CERTIFICATES_GET,
            LEG_UPLOAD,
            LEG_STATUS,
            BUNDLE_SUBMIT,
        ] {
            assert_eq!(route.admission(), AdmissionPolicy::AuthenticatedAccount);
            assert_eq!(
                route.authentication(),
                AuthenticationPolicy::CanonicalAccountSignature
            );
            assert!(route.requires_private_no_store());
        }
        for route in [AUDITOR_CAPSULE, AUDITOR_APPROVAL] {
            assert_eq!(route.admission(), AdmissionPolicy::GovernedAuditor);
            assert_eq!(
                route.authentication(),
                AuthenticationPolicy::IdentityBoundSignature
            );
            assert!(route.requires_private_no_store());
        }
        assert_eq!(
            COMMITTEE_PROOF.admission(),
            AdmissionPolicy::ValidatorRosterMember
        );
        assert_eq!(
            COMMITTEE_PROOF.authentication(),
            AuthenticationPolicy::IdentityBoundSignature
        );
        assert!(COMMITTEE_PROOF.requires_private_no_store());
    }

    #[test]
    fn only_redacted_bundle_reads_are_public() {
        for route in [BUNDLE_STATUS, BUNDLE_RECEIPT] {
            assert_eq!(route.effect(), RouteEffect::ReadOnly);
            assert_eq!(route.admission(), AdmissionPolicy::Public);
        }
    }
}
