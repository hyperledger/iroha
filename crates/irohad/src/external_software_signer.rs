//! Isolated authenticated software signing for SoraFS runtime roles.
//!
//! The service keeps private keys outside node configuration and ledger state. A deployment
//! supplies a 256-bit wrapping key through an inherited descriptor or a systemd credential. The
//! process decrypts one role-bound key envelope in memory, serves only that role on
//! peer-credential-authenticated Unix sockets, and persists a payload-free predecessor-bound audit
//! chain before reporting a mutating operation as successful.
//!
//! The broker adapter implements the existing native transaction signer traits,
//! so replacing this software backend with another signing provider does not change
//! Torii or runtime-provider registry interfaces.
#[cfg(unix)]
mod adapter;
#[cfg(unix)]
mod consensus_threshold;
mod envelope;
#[cfg(unix)]
mod journal;
#[cfg(unix)]
mod musubi_attestation;
mod musubi_subject;
mod protocol;
#[cfg(unix)]
mod runtime_adapters;
#[cfg(unix)]
mod runtime_backends;
#[cfg(unix)]
mod service;
#[cfg(unix)]
mod typed_payload;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use adapter::{
    ExternalSoftwareSignerAdapterErrorV1, ExternalSoftwareSignerNativeAdapterV1,
    ExternalSoftwareSignerNativeBackendsV1,
};
#[cfg(all(test, unix))]
pub(crate) use consensus_threshold::tests::{
    consensus_threshold_beacon_broker_max_committee_test_fixture_v1,
    consensus_threshold_beacon_broker_test_fixture_v1,
    consensus_threshold_beacon_readiness_broker_test_fixture_v1,
};
#[cfg(unix)]
pub use consensus_threshold::{
    GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1, RuntimeConsensusThresholdSignerBackendsV1,
    RuntimeConsensusThresholdSignerCredentialErrorV1, RuntimePreparedGlobalBeaconCredentialV1,
    encode_consensus_threshold_credential_bundle_v1,
    prepare_global_beacon_transition_credential_v1,
};
#[cfg(unix)]
pub(crate) use consensus_threshold::{
    decode_global_beacon_runtime_signer_v1, dispatch_beacon_custody_preparation_if_requested,
};
pub use envelope::{
    SoftwareSignerEnvelopeErrorV1, SoftwareSignerKeyEnvelopeV1, SoftwareSignerWrappingKeyV1,
};
#[cfg(unix)]
pub use journal::SoftwareSignerJournalErrorV1;
#[cfg(unix)]
pub use musubi_attestation::ExternalSoftwareSignerMusubiProviderAttestationAdapterV1;
pub use protocol::{
    ExternalSignerBackendV1, SORAFS_FOUNDATIONAL_PROMOTION_DOMAIN_V1, SignerKeyAlgorithmV1,
    SignerPurposeBindingV1, SignerRoleV1, SignerValueParseErrorV1, SoftwareSignerLiveProvenanceV1,
    SoftwareSignerPublicBindingV1,
};
#[cfg(unix)]
pub use runtime_adapters::{
    ExternalSoftwareSignerBillingStatementAdapterV1, ExternalSoftwareSignerEvidenceViewerAdapterV1,
    ExternalSoftwareSignerGovernanceDagAdapterV1, ExternalSoftwareSignerPopIssuerAdapterV1,
    ExternalSoftwareSignerPopRegistryV1, ExternalSoftwareSignerPotrGatewayAdapterV1,
    ExternalSoftwareSignerPotrProviderAdapterV1,
};
#[cfg(unix)]
pub use runtime_backends::ExternalSoftwareSignerBackendsV1;
#[cfg(unix)]
pub use service::{
    SoftwareSignerAdminErrorV1, SoftwareSignerErrorV1, SoftwareSignerProvisioningV1,
    SoftwareSignerServiceV1,
};
#[cfg(unix)]
pub use typed_payload::SoftwareSignerPurposeV1;
#[cfg(unix)]
pub use unix::{
    ExternalSoftwareSignerClientErrorV1, SoftwareSignerAdministratorClientV1,
    SoftwareSignerClientV1, SoftwareSignerEndpointPolicyV1, SoftwareSignerRotationRequestV1,
    SoftwareSignerServerErrorV1, SoftwareSignerServerV1, SoftwareSignerSignatureReceiptV1,
    load_software_signer_wrapping_key_from_credential_v1,
    load_software_signer_wrapping_key_from_fd_v1,
};
#[cfg(all(test, unix))]
mod runtime_adapter_tests;
#[cfg(all(test, unix))]
mod tests;
