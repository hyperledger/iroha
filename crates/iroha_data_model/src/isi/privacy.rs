//! Canonical first-release privacy governance and proof-admission instructions.
//!
//! These instructions expose only typed V1 privacy records. They intentionally have no string
//! protocol selectors, compatibility aliases, or opaque proof bodies.
use super::*;
use crate::privacy::{
    BootleLanternIssuerPolicyV1, PrivacyBootleLanternIssuerPolicyDigestV1,
    PrivacyConsensusLimitsV1, PrivacyExact12QualificationRecordV1, PrivacyOrchardPoolBootstrapV1,
    PrivacyPgcAccountBootstrapV1, PrivacyPgcBootstrapProofBytesV1, PrivacyProofEnvelopeV1,
    PrivacyProofManagedPoolBootstrapV1, PrivacyProtocolActivationLimitsV1,
    PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1,
    PrivacyRootPublicationV1, PrivacyVegaIssuerRecordDigestV1, PrivacyVegaIssuerRecordV1,
    PrivacyZkAcePolicyRecordDigestV1, PrivacyZkAcePolicyRecordV1, PrivacyZkAmsRegistryBootstrapV1,
    PrivacyZkX509CertificatePolicyRecordDigestV1, PrivacyZkX509CertificatePolicyRecordV1,
    PrivacyZkX509CrlRecordDigestV1, PrivacyZkX509CrlRecordV1,
    PrivacyZkX509TrustAnchorRecordDigestV1, PrivacyZkX509TrustAnchorRecordV1,
};

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
isi! {
    /// Register one immutable proposal for explicit governed activation.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyProtocolActivationV1")]
    pub struct RegisterPrivacyProtocolActivationV1 {
        /// Exact protocol, artifacts, lifecycle, and admission limits to register.
        pub activation: PrivacyProtocolActivationRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyProtocolActivationV1 {}
impl RegisterPrivacyProtocolActivationV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_protocol_activation.v1";
    /// Construct an activation-registration instruction.
    #[must_use]
    pub fn new(activation: PrivacyProtocolActivationRecordV1) -> Self {
        Self { activation }
    }
}
isi! {
    /// Register the one immutable Exact12 release and deployment qualification.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyExact12QualificationV1")]
    pub struct RegisterPrivacyExact12QualificationV1 {
        /// Full portable release and target-network deployment evidence.
        pub qualification: PrivacyExact12QualificationRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyExact12QualificationV1 {}
impl RegisterPrivacyExact12QualificationV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_exact12_qualification.v1";
    /// Construct the singleton qualification-registration instruction.
    #[must_use]
    pub fn new(qualification: PrivacyExact12QualificationRecordV1) -> Self {
        Self { qualification }
    }
}
isi! {
    /// Schedule a component-wise tightening of the chain-wide privacy policy for a future block.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::SchedulePrivacyConsensusPolicyTighteningV1")]
    pub struct SchedulePrivacyConsensusPolicyTighteningV1 {
        /// Exact incoming height strictly after admission; the next block is allowed.
        pub effective_at_height: u64,
        /// Complete component-wise-lower successor limits.
        pub next_limits: PrivacyConsensusLimitsV1,
    }
}
impl crate::seal::Instruction for SchedulePrivacyConsensusPolicyTighteningV1 {}
impl SchedulePrivacyConsensusPolicyTighteningV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.schedule_consensus_policy_tightening.v1";
    /// Construct a chain-wide privacy-policy schedule.
    #[must_use]
    pub const fn new(effective_at_height: u64, next_limits: PrivacyConsensusLimitsV1) -> Self {
        Self {
            effective_at_height,
            next_limits,
        }
    }
}
isi! {
    /// Schedule a component-wise tightening for one privacy protocol at a future block.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::SchedulePrivacyProtocolLimitsTighteningV1")]
    pub struct SchedulePrivacyProtocolLimitsTighteningV1 {
        /// Exact registered protocol whose limits will be tightened.
        pub protocol_id: PrivacyProtocolIdV1,
        /// Exact incoming height strictly after admission; the next block is allowed.
        pub effective_at_height: u64,
        /// Complete protocol-tagged successor limits.
        pub next_limits: PrivacyProtocolActivationLimitsV1,
    }
}
impl crate::seal::Instruction for SchedulePrivacyProtocolLimitsTighteningV1 {}
impl SchedulePrivacyProtocolLimitsTighteningV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.schedule_protocol_limits_tightening.v1";
    /// Construct a protocol-specific limit schedule.
    #[must_use]
    pub const fn new(
        protocol_id: PrivacyProtocolIdV1,
        effective_at_height: u64,
        next_limits: PrivacyProtocolActivationLimitsV1,
    ) -> Self {
        Self {
            protocol_id,
            effective_at_height,
            next_limits,
        }
    }
}
isi! {
    /// Apply a forward-only lifecycle transition to a registered privacy protocol.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::TransitionPrivacyProtocolLifecycleV1")]
    pub struct TransitionPrivacyProtocolLifecycleV1 {
        /// Exact protocol whose lifecycle is changing.
        pub protocol_id: PrivacyProtocolIdV1,
        /// Complete next lifecycle state, including its effective height.
        pub next_lifecycle: PrivacyProtocolLifecycleV1,
    }
}
impl crate::seal::Instruction for TransitionPrivacyProtocolLifecycleV1 {}
impl TransitionPrivacyProtocolLifecycleV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.transition_protocol_lifecycle.v1";
    /// Construct a lifecycle-transition instruction.
    #[must_use]
    pub fn new(
        protocol_id: PrivacyProtocolIdV1,
        next_lifecycle: PrivacyProtocolLifecycleV1,
    ) -> Self {
        Self {
            protocol_id,
            next_lifecycle,
        }
    }
}
isi! {
    /// Publish or initialize one governance-authorized canonical privacy root.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::PublishPrivacyRootV1")]
    pub struct PublishPrivacyRootV1 {
        /// Exact namespace, role, epoch, and root publication.
        pub publication: PrivacyRootPublicationV1,
    }
}
impl crate::seal::Instruction for PublishPrivacyRootV1 {}
impl PublishPrivacyRootV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.publish_root.v1";
    /// Construct a governed root-publication instruction.
    #[must_use]
    pub fn new(publication: PrivacyRootPublicationV1) -> Self {
        Self { publication }
    }
}
isi! {
    /// Bootstrap one governed Orchard V3 pool at the node-derived empty root.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::BootstrapPrivacyOrchardPoolV1")]
    pub struct BootstrapPrivacyOrchardPoolV1 {
        /// Immutable pool, public asset, and reserve-account binding.
        pub bootstrap: PrivacyOrchardPoolBootstrapV1,
    }
}
impl crate::seal::Instruction for BootstrapPrivacyOrchardPoolV1 {}
impl BootstrapPrivacyOrchardPoolV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.bootstrap_orchard_pool.v1";
    /// Construct a governed Orchard pool bootstrap.
    #[must_use]
    pub fn new(bootstrap: PrivacyOrchardPoolBootstrapV1) -> Self {
        Self { bootstrap }
    }
}
isi! {
    /// Bootstrap one governed FCMP++, private-IVM, or PQ-MASP pool at its node-derived empty root.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::BootstrapPrivacyProofManagedPoolV1")]
    pub struct BootstrapPrivacyProofManagedPoolV1 {
        /// Exact closed protocol, namespace, asset, and optional program/reserve binding.
        pub bootstrap: PrivacyProofManagedPoolBootstrapV1,
    }
}
impl crate::seal::Instruction for BootstrapPrivacyProofManagedPoolV1 {}
impl BootstrapPrivacyProofManagedPoolV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.bootstrap_proof_managed_pool.v1";
    /// Construct a governed proof-managed pool bootstrap.
    #[must_use]
    pub fn new(bootstrap: PrivacyProofManagedPoolBootstrapV1) -> Self {
        Self { bootstrap }
    }
}
isi! {
    /// Bootstrap one complete governed Anonymous PGC encrypted-account table.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::BootstrapPrivacyPgcAccountsV1")]
    pub struct BootstrapPrivacyPgcAccountsV1 {
        /// Complete canonical pool namespace, root, epoch, and ordered accounts.
        pub bootstrap: PrivacyPgcAccountBootstrapV1,
        /// Exact canonical native proof of account well-formedness, range, and supply.
        pub proof: PrivacyPgcBootstrapProofBytesV1,
    }
}
impl crate::seal::Instruction for BootstrapPrivacyPgcAccountsV1 {}
impl BootstrapPrivacyPgcAccountsV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.bootstrap_pgc_accounts.v1";
    /// Construct a governed Anonymous PGC account bootstrap.
    #[must_use]
    pub fn new(
        bootstrap: PrivacyPgcAccountBootstrapV1,
        proof: PrivacyPgcBootstrapProofBytesV1,
    ) -> Self {
        Self { bootstrap, proof }
    }
}
isi! {
    /// Atomically initialize one governed ZK-AMS issuer, policy, and admitted-identity registry.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::BootstrapPrivacyZkAmsRegistryV1")]
    pub struct BootstrapPrivacyZkAmsRegistryV1 {
        /// Exact issuer key, policy digest, namespace, root, and origin epoch.
        pub bootstrap: PrivacyZkAmsRegistryBootstrapV1,
    }
}
impl crate::seal::Instruction for BootstrapPrivacyZkAmsRegistryV1 {}
impl BootstrapPrivacyZkAmsRegistryV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.bootstrap_zk_ams_registry.v1";
    /// Construct a governed ZK-AMS registry bootstrap.
    #[must_use]
    pub const fn new(bootstrap: PrivacyZkAmsRegistryBootstrapV1) -> Self {
        Self { bootstrap }
    }
}
isi! {
    /// Register one canonical authoritative ZK-ACE policy lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyZkAcePolicyV1")]
    pub struct RegisterPrivacyZkAcePolicyV1 {
        /// Complete active origin record, including its canonical self-digest.
        pub policy: PrivacyZkAcePolicyRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyZkAcePolicyV1 {}
impl RegisterPrivacyZkAcePolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_zk_ace_policy.v1";
    /// Construct an authoritative policy registration.
    #[must_use]
    pub fn new(policy: PrivacyZkAcePolicyRecordV1) -> Self {
        Self { policy }
    }
}
isi! {
    /// Rotate one active authoritative ZK-ACE policy by exactly one epoch.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RotatePrivacyZkAcePolicyV1")]
    pub struct RotatePrivacyZkAcePolicyV1 {
        /// Exact self-digest of the active record being replaced.
        pub expected_current_record_digest: PrivacyZkAcePolicyRecordDigestV1,
        /// Complete active successor record.
        pub successor: PrivacyZkAcePolicyRecordV1,
    }
}
impl crate::seal::Instruction for RotatePrivacyZkAcePolicyV1 {}
impl RotatePrivacyZkAcePolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.rotate_zk_ace_policy.v1";
    /// Construct an exact policy rotation.
    #[must_use]
    pub fn new(
        expected_current_record_digest: PrivacyZkAcePolicyRecordDigestV1,
        successor: PrivacyZkAcePolicyRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Irreversibly revoke one active authoritative ZK-ACE policy.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RevokePrivacyZkAcePolicyV1")]
    pub struct RevokePrivacyZkAcePolicyV1 {
        /// Exact self-digest of the active record being revoked.
        pub expected_current_record_digest: PrivacyZkAcePolicyRecordDigestV1,
        /// Complete revoked successor record at the next epoch.
        pub successor: PrivacyZkAcePolicyRecordV1,
    }
}
impl crate::seal::Instruction for RevokePrivacyZkAcePolicyV1 {}
impl RevokePrivacyZkAcePolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.revoke_zk_ace_policy.v1";
    /// Construct an exact irreversible policy revocation.
    #[must_use]
    pub fn new(
        expected_current_record_digest: PrivacyZkAcePolicyRecordDigestV1,
        successor: PrivacyZkAcePolicyRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Register one canonical authoritative Bootle/Lantern issuer-policy lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyBootleLanternIssuerPolicyV1")]
    pub struct RegisterPrivacyBootleLanternIssuerPolicyV1 {
        /// Complete active origin policy, including its canonical self-digest.
        pub policy: BootleLanternIssuerPolicyV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyBootleLanternIssuerPolicyV1 {}
impl RegisterPrivacyBootleLanternIssuerPolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_bootle_lantern_issuer_policy.v1";
    /// Construct an authoritative issuer-policy registration.
    #[must_use]
    pub fn new(policy: BootleLanternIssuerPolicyV1) -> Self {
        Self { policy }
    }
}
isi! {
    /// Rotate one active Bootle/Lantern issuer-policy lineage by exactly one epoch.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RotatePrivacyBootleLanternIssuerPolicyV1")]
    pub struct RotatePrivacyBootleLanternIssuerPolicyV1 {
        /// Exact self-digest of the active policy being replaced.
        pub expected_current_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
        /// Complete active successor policy.
        pub successor: BootleLanternIssuerPolicyV1,
    }
}
impl crate::seal::Instruction for RotatePrivacyBootleLanternIssuerPolicyV1 {}
impl RotatePrivacyBootleLanternIssuerPolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.rotate_bootle_lantern_issuer_policy.v1";
    /// Construct an exact issuer-policy compare-and-swap rotation.
    #[must_use]
    pub fn new(
        expected_current_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
        successor: BootleLanternIssuerPolicyV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Irreversibly revoke one active Bootle/Lantern issuer-policy lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RevokePrivacyBootleLanternIssuerPolicyV1")]
    pub struct RevokePrivacyBootleLanternIssuerPolicyV1 {
        /// Exact self-digest of the active policy being revoked.
        pub expected_current_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
        /// Complete terminal successor policy.
        pub successor: BootleLanternIssuerPolicyV1,
    }
}
impl crate::seal::Instruction for RevokePrivacyBootleLanternIssuerPolicyV1 {}
impl RevokePrivacyBootleLanternIssuerPolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.revoke_bootle_lantern_issuer_policy.v1";
    /// Construct an exact irreversible issuer-policy revocation.
    #[must_use]
    pub fn new(
        expected_current_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
        successor: BootleLanternIssuerPolicyV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Register one canonical authoritative Vega issuer-key/policy lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyVegaIssuerV1")]
    pub struct RegisterPrivacyVegaIssuerV1 {
        /// Complete active origin revision, including its canonical self-digest.
        pub record: PrivacyVegaIssuerRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyVegaIssuerV1 {}
impl RegisterPrivacyVegaIssuerV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_vega_issuer.v1";
    /// Construct an authoritative Vega issuer registration.
    #[must_use]
    pub const fn new(record: PrivacyVegaIssuerRecordV1) -> Self {
        Self { record }
    }
}
isi! {
    /// Rotate one active Vega issuer lineage by exactly one immutable epoch.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RotatePrivacyVegaIssuerV1")]
    pub struct RotatePrivacyVegaIssuerV1 {
        /// Exact self-digest of the active revision being replaced.
        pub expected_current_record_digest: PrivacyVegaIssuerRecordDigestV1,
        /// Complete active successor revision.
        pub successor: PrivacyVegaIssuerRecordV1,
    }
}
impl crate::seal::Instruction for RotatePrivacyVegaIssuerV1 {}
impl RotatePrivacyVegaIssuerV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.rotate_vega_issuer.v1";
    /// Construct an exact Vega issuer compare-and-swap rotation.
    #[must_use]
    pub const fn new(
        expected_current_record_digest: PrivacyVegaIssuerRecordDigestV1,
        successor: PrivacyVegaIssuerRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Irreversibly revoke one active Vega issuer lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito (deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RevokePrivacyVegaIssuerV1")]
    pub struct RevokePrivacyVegaIssuerV1 {
        /// Exact self-digest of the active revision being revoked.
        pub expected_current_record_digest: PrivacyVegaIssuerRecordDigestV1,
        /// Complete terminal successor revision.
        pub successor: PrivacyVegaIssuerRecordV1,
    }
}
impl crate::seal::Instruction for RevokePrivacyVegaIssuerV1 {}
impl RevokePrivacyVegaIssuerV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.revoke_vega_issuer.v1";
    /// Construct an exact irreversible Vega issuer revocation.
    #[must_use]
    pub const fn new(
        expected_current_record_digest: PrivacyVegaIssuerRecordDigestV1,
        successor: PrivacyVegaIssuerRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Register one canonical authoritative X.509 trust-anchor lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyZkX509TrustAnchorV1")]
    pub struct RegisterPrivacyZkX509TrustAnchorV1 {
        /// Complete active origin revision, including its canonical self-digest.
        pub record: PrivacyZkX509TrustAnchorRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyZkX509TrustAnchorV1 {}
impl RegisterPrivacyZkX509TrustAnchorV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_zk_x509_trust_anchor.v1";
    /// Construct an authoritative trust-anchor registration.
    #[must_use]
    pub const fn new(record: PrivacyZkX509TrustAnchorRecordV1) -> Self {
        Self { record }
    }
}
isi! {
    /// Rotate one active X.509 trust-anchor lineage by exactly one epoch.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RotatePrivacyZkX509TrustAnchorV1")]
    pub struct RotatePrivacyZkX509TrustAnchorV1 {
        /// Exact self-digest of the active revision being replaced.
        pub expected_current_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
        /// Complete active successor revision.
        pub successor: PrivacyZkX509TrustAnchorRecordV1,
    }
}
impl crate::seal::Instruction for RotatePrivacyZkX509TrustAnchorV1 {}
impl RotatePrivacyZkX509TrustAnchorV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.rotate_zk_x509_trust_anchor.v1";
    /// Construct an exact trust-anchor rotation.
    #[must_use]
    pub const fn new(
        expected_current_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
        successor: PrivacyZkX509TrustAnchorRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Irreversibly revoke one active X.509 trust-anchor lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RevokePrivacyZkX509TrustAnchorV1")]
    pub struct RevokePrivacyZkX509TrustAnchorV1 {
        /// Exact self-digest of the active revision being revoked.
        pub expected_current_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
        /// Complete terminal successor revision.
        pub successor: PrivacyZkX509TrustAnchorRecordV1,
    }
}
impl crate::seal::Instruction for RevokePrivacyZkX509TrustAnchorV1 {}
impl RevokePrivacyZkX509TrustAnchorV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.revoke_zk_x509_trust_anchor.v1";
    /// Construct an irreversible trust-anchor revocation.
    #[must_use]
    pub const fn new(
        expected_current_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
        successor: PrivacyZkX509TrustAnchorRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Register one canonical authoritative X.509 certificate-policy lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyZkX509CertificatePolicyV1")]
    pub struct RegisterPrivacyZkX509CertificatePolicyV1 {
        /// Complete active origin revision, including its canonical self-digest.
        pub record: PrivacyZkX509CertificatePolicyRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyZkX509CertificatePolicyV1 {}
impl RegisterPrivacyZkX509CertificatePolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_zk_x509_certificate_policy.v1";
    /// Construct an authoritative certificate-policy registration.
    #[must_use]
    pub fn new(record: PrivacyZkX509CertificatePolicyRecordV1) -> Self {
        Self { record }
    }
}
isi! {
    /// Rotate one active X.509 certificate-policy lineage by exactly one epoch.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RotatePrivacyZkX509CertificatePolicyV1")]
    pub struct RotatePrivacyZkX509CertificatePolicyV1 {
        /// Exact self-digest of the active revision being replaced.
        pub expected_current_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
        /// Complete active successor revision.
        pub successor: PrivacyZkX509CertificatePolicyRecordV1,
    }
}
impl crate::seal::Instruction for RotatePrivacyZkX509CertificatePolicyV1 {}
impl RotatePrivacyZkX509CertificatePolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.rotate_zk_x509_certificate_policy.v1";
    /// Construct an exact certificate-policy rotation.
    #[must_use]
    pub fn new(
        expected_current_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
        successor: PrivacyZkX509CertificatePolicyRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Irreversibly revoke one active X.509 certificate-policy lineage.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RevokePrivacyZkX509CertificatePolicyV1")]
    pub struct RevokePrivacyZkX509CertificatePolicyV1 {
        /// Exact self-digest of the active revision being revoked.
        pub expected_current_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
        /// Complete terminal successor revision.
        pub successor: PrivacyZkX509CertificatePolicyRecordV1,
    }
}
impl crate::seal::Instruction for RevokePrivacyZkX509CertificatePolicyV1 {}
impl RevokePrivacyZkX509CertificatePolicyV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.revoke_zk_x509_certificate_policy.v1";
    /// Construct an irreversible certificate-policy revocation.
    #[must_use]
    pub fn new(
        expected_current_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
        successor: PrivacyZkX509CertificatePolicyRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Register one current issuer-scoped X.509 signed-CRL lineage.
    ///
    /// Execution atomically installs the record and its exact revoked-serial
    /// root; generic root publication cannot substitute either component.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RegisterPrivacyZkX509CrlV1")]
    pub struct RegisterPrivacyZkX509CrlV1 {
        /// Complete active origin record, including its root and self-digest.
        pub record: PrivacyZkX509CrlRecordV1,
    }
}
impl crate::seal::Instruction for RegisterPrivacyZkX509CrlV1 {}
impl RegisterPrivacyZkX509CrlV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.register_zk_x509_crl.v1";
    /// Construct an atomic signed-CRL lineage registration.
    #[must_use]
    pub const fn new(record: PrivacyZkX509CrlRecordV1) -> Self {
        Self { record }
    }
}
isi! {
    /// Rotate one current signed-CRL lineage and root by exactly one epoch.
    ///
    /// The expected digest provides compare-and-swap semantics. Execution
    /// atomically replaces the current record and appends its exact root.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RotatePrivacyZkX509CrlV1")]
    pub struct RotatePrivacyZkX509CrlV1 {
        /// Exact self-digest of the current record being replaced.
        pub expected_current_record_digest: PrivacyZkX509CrlRecordDigestV1,
        /// Complete active successor record and root.
        pub successor: PrivacyZkX509CrlRecordV1,
    }
}
impl crate::seal::Instruction for RotatePrivacyZkX509CrlV1 {}
impl RotatePrivacyZkX509CrlV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.rotate_zk_x509_crl.v1";
    /// Construct an atomic signed-CRL compare-and-swap rotation.
    #[must_use]
    pub const fn new(
        expected_current_record_digest: PrivacyZkX509CrlRecordDigestV1,
        successor: PrivacyZkX509CrlRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Irreversibly revoke one current signed-CRL lineage.
    ///
    /// Execution atomically installs the terminal successor while preserving
    /// the last active root head, leaving no active proof snapshot.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::RevokePrivacyZkX509CrlV1")]
    pub struct RevokePrivacyZkX509CrlV1 {
        /// Exact self-digest of the current record being revoked.
        pub expected_current_record_digest: PrivacyZkX509CrlRecordDigestV1,
        /// Complete terminal successor record.
        pub successor: PrivacyZkX509CrlRecordV1,
    }
}
impl crate::seal::Instruction for RevokePrivacyZkX509CrlV1 {}
impl RevokePrivacyZkX509CrlV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.revoke_zk_x509_crl.v1";
    /// Construct an atomic irreversible signed-CRL revocation.
    #[must_use]
    pub const fn new(
        expected_current_record_digest: PrivacyZkX509CrlRecordDigestV1,
        successor: PrivacyZkX509CrlRecordV1,
    ) -> Self {
        Self {
            expected_current_record_digest,
            successor,
        }
    }
}
isi! {
    /// Verify and atomically apply one protocol-typed privacy proof action.
    #[derive (DeriveJsonSerialize , DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::privacy::SubmitPrivacyProofV1")]
    pub struct SubmitPrivacyProofV1 {
        /// Complete governed-artifact-bound statement and native proof.
        pub envelope: PrivacyProofEnvelopeV1,
    }
}
impl crate::seal::Instruction for SubmitPrivacyProofV1 {}
impl SubmitPrivacyProofV1 {
    /// Canonical first-release Norito instruction identifier.
    pub const WIRE_ID: &'static str = "iroha.privacy.submit_proof.v1";
    /// Allocation bound for a canonical instruction carrying a maximum-sized envelope.
    ///
    /// Consensus privacy bytes charge the complete envelope frame. This one-field wrapper
    /// has the same alignment and replaces that frame header with its own, adding only the
    /// envelope field's canonical length prefix. Using the complete envelope bound for that
    /// prefix is conservative even at a compact-length transition. This is a codec bound,
    /// not proof validation or admission under a possibly tighter committed policy.
    #[must_use]
    pub fn canonical_frame_byte_limit_v1() -> usize {
        let envelope_limit = crate::privacy::TAIRA_PRIVACY_MAX_ACTION_BYTES_V1 as usize;
        envelope_limit
            + norito::core::len_prefix_len_with_flags(
                envelope_limit,
                norito::core::default_encode_flags(),
            )
    }
    /// Construct a privacy-proof submission instruction.
    #[must_use]
    pub fn new(envelope: PrivacyProofEnvelopeV1) -> Self {
        Self { envelope }
    }
}
fn privacy_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_privacy_decode_from_slice {
    ($ty:ident { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = privacy_decode_flags();
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?,
                        flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field),+ }, offset))
            }
        }
    };
}
impl_privacy_decode_from_slice!(RegisterPrivacyProtocolActivationV1 {
    activation: PrivacyProtocolActivationRecordV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyExact12QualificationV1 {
    qualification: PrivacyExact12QualificationRecordV1,
});
impl_privacy_decode_from_slice!(SchedulePrivacyConsensusPolicyTighteningV1 {
    effective_at_height: u64,
    next_limits: PrivacyConsensusLimitsV1,
});
impl_privacy_decode_from_slice!(SchedulePrivacyProtocolLimitsTighteningV1 {
    protocol_id: PrivacyProtocolIdV1,
    effective_at_height: u64,
    next_limits: PrivacyProtocolActivationLimitsV1,
});
impl_privacy_decode_from_slice!(TransitionPrivacyProtocolLifecycleV1 {
    protocol_id: PrivacyProtocolIdV1,
    next_lifecycle: PrivacyProtocolLifecycleV1,
});
impl_privacy_decode_from_slice!(PublishPrivacyRootV1 {
    publication: PrivacyRootPublicationV1,
});
impl_privacy_decode_from_slice!(BootstrapPrivacyOrchardPoolV1 {
    bootstrap: PrivacyOrchardPoolBootstrapV1,
});
impl_privacy_decode_from_slice!(BootstrapPrivacyProofManagedPoolV1 {
    bootstrap: PrivacyProofManagedPoolBootstrapV1,
});
impl_privacy_decode_from_slice!(BootstrapPrivacyPgcAccountsV1 {
    bootstrap: PrivacyPgcAccountBootstrapV1,
    proof: PrivacyPgcBootstrapProofBytesV1,
});
impl_privacy_decode_from_slice!(BootstrapPrivacyZkAmsRegistryV1 {
    bootstrap: PrivacyZkAmsRegistryBootstrapV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyZkAcePolicyV1 {
    policy: PrivacyZkAcePolicyRecordV1,
});
impl_privacy_decode_from_slice!(RotatePrivacyZkAcePolicyV1 {
    expected_current_record_digest: PrivacyZkAcePolicyRecordDigestV1,
    successor: PrivacyZkAcePolicyRecordV1,
});
impl_privacy_decode_from_slice!(RevokePrivacyZkAcePolicyV1 {
    expected_current_record_digest: PrivacyZkAcePolicyRecordDigestV1,
    successor: PrivacyZkAcePolicyRecordV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyBootleLanternIssuerPolicyV1 {
    policy: BootleLanternIssuerPolicyV1,
});
impl_privacy_decode_from_slice!(RotatePrivacyBootleLanternIssuerPolicyV1 {
    expected_current_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
    successor: BootleLanternIssuerPolicyV1,
});
impl_privacy_decode_from_slice!(RevokePrivacyBootleLanternIssuerPolicyV1 {
    expected_current_record_digest: PrivacyBootleLanternIssuerPolicyDigestV1,
    successor: BootleLanternIssuerPolicyV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyVegaIssuerV1 {
    record: PrivacyVegaIssuerRecordV1,
});
impl_privacy_decode_from_slice!(RotatePrivacyVegaIssuerV1 {
    expected_current_record_digest: PrivacyVegaIssuerRecordDigestV1,
    successor: PrivacyVegaIssuerRecordV1,
});
impl_privacy_decode_from_slice!(RevokePrivacyVegaIssuerV1 {
    expected_current_record_digest: PrivacyVegaIssuerRecordDigestV1,
    successor: PrivacyVegaIssuerRecordV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyZkX509TrustAnchorV1 {
    record: PrivacyZkX509TrustAnchorRecordV1,
});
impl_privacy_decode_from_slice!(RotatePrivacyZkX509TrustAnchorV1 {
    expected_current_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
    successor: PrivacyZkX509TrustAnchorRecordV1,
});
impl_privacy_decode_from_slice!(RevokePrivacyZkX509TrustAnchorV1 {
    expected_current_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1,
    successor: PrivacyZkX509TrustAnchorRecordV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyZkX509CertificatePolicyV1 {
    record: PrivacyZkX509CertificatePolicyRecordV1,
});
impl_privacy_decode_from_slice!(RotatePrivacyZkX509CertificatePolicyV1 {
    expected_current_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
    successor: PrivacyZkX509CertificatePolicyRecordV1,
});
impl_privacy_decode_from_slice!(RevokePrivacyZkX509CertificatePolicyV1 {
    expected_current_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1,
    successor: PrivacyZkX509CertificatePolicyRecordV1,
});
impl_privacy_decode_from_slice!(RegisterPrivacyZkX509CrlV1 {
    record: PrivacyZkX509CrlRecordV1,
});
impl_privacy_decode_from_slice!(RotatePrivacyZkX509CrlV1 {
    expected_current_record_digest: PrivacyZkX509CrlRecordDigestV1,
    successor: PrivacyZkX509CrlRecordV1,
});
impl_privacy_decode_from_slice!(RevokePrivacyZkX509CrlV1 {
    expected_current_record_digest: PrivacyZkX509CrlRecordDigestV1,
    successor: PrivacyZkX509CrlRecordV1,
});
impl_privacy_decode_from_slice!(SubmitPrivacyProofV1 {
    envelope: PrivacyProofEnvelopeV1,
});
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetDefinitionId, NetworkId,
        account::AccountId,
        asset::AssetBalanceScope,
        block::BlockHeader,
        privacy::{
            BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1, BOOTLE_LANTERN_RING_DEGREE_V1,
            BootleLanternAllowedAttributeValuesV1, BootleLanternAttributeValueV1,
            BootleLanternIssuerPolicyLifecycleV1, BootleLanternIssuerPublicMatrixV1,
            BootleLanternPolynomialV1, IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1,
            IrohaJindoPolynomialCommitmentStatementV1, JindoActivationLimitsV1,
            PrivacyActiveLifecycleV1, PrivacyBootleLanternIssuerPolicyDigestV1,
            PrivacyConsensusLimitsV1, PrivacyEngineManifestDigestV1, PrivacyFcmpOutputTupleV1,
            PrivacyFcmpPoolBootstrapV1, PrivacyIssuerIdV1, PrivacyJindoFieldElementV1,
            PrivacyJindoLatticeCommitmentV1, PrivacyNamespaceScopeV1, PrivacyNamespaceV1,
            PrivacyOrchardPoolBootstrapV1, PrivacyP256CiphertextV1, PrivacyP256PointV1,
            PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPgcAccountBootstrapV1,
            PrivacyPgcAccountV1, PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyPoolIdV1,
            PrivacyPoolNamespaceV1, PrivacyProofBytesV1, PrivacyProofManagedPoolBootstrapV1,
            PrivacyProofV1, PrivacyProposedLifecycleV1, PrivacyProtocolActivationLimitsV1,
            PrivacyRootRoleV1, PrivacyRootV1, PrivacyStatementContextV1,
            PrivacyStatementSchemaDigestV1, PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
            PrivacyVegaIssuerRecordLifecycleV1, PrivacyVegaMdlDigestAlgorithmV1,
            PrivacyVegaMdlNamespaceV1, PrivacyVegaMdlSignatureAlgorithmV1, PrivacyVerifierDigestV1,
            PrivacyX509CrlDerDigestV1, PrivacyX509CrlIssuerSpkiDigestV1,
            PrivacyX509ExtendedKeyUsageV1, PrivacyX509KeyUsageRequirementV1, PrivacyX509KeyUsageV1,
            PrivacyX509TrustStoreDigestV1, PrivacyZkAceIdentityCommitmentV1,
            PrivacyZkAcePolicyLifecycleV1, PrivacyZkAmsRegistryIdV1,
            PrivacyZkX509RecordLifecycleV1,
        },
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use norito::core::DecodeFromSlice;
    use std::str::FromStr as _;
    const PRIVACY_ISI_WIRE_IDS_V1: [&str; 29] = [
        RegisterPrivacyProtocolActivationV1::WIRE_ID,
        RegisterPrivacyExact12QualificationV1::WIRE_ID,
        SchedulePrivacyConsensusPolicyTighteningV1::WIRE_ID,
        SchedulePrivacyProtocolLimitsTighteningV1::WIRE_ID,
        TransitionPrivacyProtocolLifecycleV1::WIRE_ID,
        PublishPrivacyRootV1::WIRE_ID,
        BootstrapPrivacyOrchardPoolV1::WIRE_ID,
        BootstrapPrivacyProofManagedPoolV1::WIRE_ID,
        BootstrapPrivacyPgcAccountsV1::WIRE_ID,
        BootstrapPrivacyZkAmsRegistryV1::WIRE_ID,
        RegisterPrivacyZkAcePolicyV1::WIRE_ID,
        RotatePrivacyZkAcePolicyV1::WIRE_ID,
        RevokePrivacyZkAcePolicyV1::WIRE_ID,
        RegisterPrivacyBootleLanternIssuerPolicyV1::WIRE_ID,
        RotatePrivacyBootleLanternIssuerPolicyV1::WIRE_ID,
        RevokePrivacyBootleLanternIssuerPolicyV1::WIRE_ID,
        RegisterPrivacyVegaIssuerV1::WIRE_ID,
        RotatePrivacyVegaIssuerV1::WIRE_ID,
        RevokePrivacyVegaIssuerV1::WIRE_ID,
        RegisterPrivacyZkX509TrustAnchorV1::WIRE_ID,
        RotatePrivacyZkX509TrustAnchorV1::WIRE_ID,
        RevokePrivacyZkX509TrustAnchorV1::WIRE_ID,
        RegisterPrivacyZkX509CertificatePolicyV1::WIRE_ID,
        RotatePrivacyZkX509CertificatePolicyV1::WIRE_ID,
        RevokePrivacyZkX509CertificatePolicyV1::WIRE_ID,
        RegisterPrivacyZkX509CrlV1::WIRE_ID,
        RotatePrivacyZkX509CrlV1::WIRE_ID,
        RevokePrivacyZkX509CrlV1::WIRE_ID,
        SubmitPrivacyProofV1::WIRE_ID,
    ];
    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("fixture seed derives an account")
                .public_key()
                .clone(),
        )
    }
    fn orchard_bootstrap() -> PrivacyOrchardPoolBootstrapV1 {
        PrivacyOrchardPoolBootstrapV1::new(
            PrivacyPoolIdV1::new(digest(23)),
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("orchard").expect("asset name"),
            ),
            AssetBalanceScope::Global,
            account(24),
        )
        .expect("canonical Orchard bootstrap")
    }
    fn proof_managed_pool_bootstrap() -> PrivacyProofManagedPoolBootstrapV1 {
        PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(PrivacyFcmpPoolBootstrapV1 {
            pool_id: PrivacyPoolIdV1::new(digest(25)),
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("fcmp").expect("asset name"),
            ),
            initial_outputs: vec![PrivacyFcmpOutputTupleV1 {
                output_key: digest(26),
                linking_tag_generator: digest(27),
                amount_commitment: digest(28),
            }],
        })
    }
    fn activation() -> PrivacyProtocolActivationRecordV1 {
        let protocol_id = PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1;
        PrivacyProtocolActivationRecordV1 {
            protocol_id,
            proof_system_id: protocol_id.expected_proof_system(),
            engine_id: protocol_id.expected_engine(),
            parameter_id: PrivacyParameterIdV1::new(digest(1)),
            parameter_digest: PrivacyParameterDigestV1::new(digest(2)),
            verifier_digest: PrivacyVerifierDigestV1::new(digest(3)),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(digest(4)),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new(digest(5)),
            lifecycle: PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
                proposed_at_height: 100,
            }),
            protocol_limits: PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                JindoActivationLimitsV1 {
                    max_polynomial_count: 4,
                },
            ),
            pending_protocol_limits_tightening: None,
        }
    }
    #[test]
    #[ignore = "opt-in capture of the current privacy activation instruction"]
    fn capture_current_privacy_activation_instruction_identity_frames() {
        let row = crate::isi::generated_record_identity_tests::capture(
            RegisterPrivacyProtocolActivationV1::new(activation()),
        );
        println!(
            "PRIVACY_ACTIVATION_INSTRUCTION_CAPTURE={}",
            norito::json::to_json(&row).expect("encode exact activation identity capture"),
        );
    }

    fn envelope() -> PrivacyProofEnvelopeV1 {
        let activation = activation();
        let context = PrivacyStatementContextV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA5; 32])),
            ),
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(digest(6)),
            parameter_id: activation.parameter_id,
            parameter_digest: activation.parameter_digest,
            verifier_digest: activation.verifier_digest,
            statement_schema_digest: activation.statement_schema_digest,
            engine_manifest_digest: activation.engine_manifest_digest,
        };
        let mut evaluation_point = [0; 32];
        evaluation_point[0] = 7;
        let polynomial_commitments = (6_i32..10)
            .map(|coefficient| {
                let mut commitment = vec![0; IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1];
                commitment[..4].copy_from_slice(&coefficient.to_le_bytes());
                PrivacyJindoLatticeCommitmentV1::new(commitment)
            })
            .collect();
        let claimed_evaluations = (8_u8..12)
            .map(|value| {
                let mut encoding = [0; 32];
                encoding[0] = value;
                PrivacyJindoFieldElementV1::new(encoding)
            })
            .collect();
        let statement = PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(
            IrohaJindoPolynomialCommitmentStatementV1 {
                context,
                polynomial_commitments,
                evaluation_point: PrivacyJindoFieldElementV1::new(evaluation_point),
                claimed_evaluations,
            },
        );
        let statement_digest = statement.digest().expect("fixture statement encodes");
        PrivacyProofEnvelopeV1 {
            wire_magic: crate::privacy::PrivacyProofWireMagicV1::default(),
            catalog_commitment: crate::privacy::PrivacyExact12CatalogCommitmentV1::default(),
            protocol_id: activation.protocol_id,
            proof_system_id: activation.proof_system_id,
            engine_id: activation.engine_id,
            parameter_id: activation.parameter_id,
            parameter_digest: activation.parameter_digest,
            verifier_digest: activation.verifier_digest,
            statement_schema_digest: activation.statement_schema_digest,
            engine_manifest_digest: activation.engine_manifest_digest,
            statement_digest,
            statement,
            proof: PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(
                vec![9],
            )),
        }
    }
    fn publication() -> PrivacyRootPublicationV1 {
        PrivacyRootPublicationV1::new(
            PrivacyNamespaceV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                    pool_id: PrivacyPoolIdV1::new(digest(20)),
                }),
            ),
            PrivacyRootRoleV1::PgcAccountState,
            1,
            PrivacyRootV1::new(digest(21)),
        )
        .expect("valid root publication")
    }
    fn p256_point(prefix: u8, final_byte: u8) -> PrivacyP256PointV1 {
        let mut bytes = [0; 33];
        bytes[0] = prefix;
        bytes[32] = final_byte;
        PrivacyP256PointV1::new(bytes)
    }
    fn pgc_bootstrap() -> PrivacyPgcAccountBootstrapV1 {
        PrivacyPgcAccountBootstrapV1 {
            namespace: publication().namespace,
            initial_root: PrivacyRootV1::new(digest(22)),
            initial_epoch: 1,
            total_supply: 160,
            accounts: (1..=16)
                .map(|index| PrivacyPgcAccountV1 {
                    public_key: p256_point(2, index),
                    encrypted_balance: PrivacyP256CiphertextV1 {
                        left: p256_point(2, index.wrapping_add(32)),
                        right: p256_point(3, index.wrapping_add(64)),
                    },
                })
                .collect(),
        }
    }
    fn zk_ams_bootstrap() -> PrivacyZkAmsRegistryBootstrapV1 {
        let bootstrap = PrivacyZkAmsRegistryBootstrapV1 {
            issuer_id: PrivacyIssuerIdV1::new(digest(30)),
            registry_id: PrivacyZkAmsRegistryIdV1::new(digest(31)),
            policy_id: PrivacyPolicyIdV1::new(digest(32)),
            issuer_public_key: p256_point(2, 33),
            policy_digest: PrivacyPolicyDigestV1::new(digest(34)),
            initial_registry_root: PrivacyRootV1::new(digest(35)),
            initial_registry_epoch: 1,
        };
        bootstrap
            .validate()
            .expect("canonical ZK-AMS registry bootstrap");
        bootstrap
    }
    fn zk_ace_policy(
        epoch: u64,
        identity_seed: u8,
        lifecycle: PrivacyZkAcePolicyLifecycleV1,
    ) -> PrivacyZkAcePolicyRecordV1 {
        let mut source_allowlist = vec![account(40), account(41), account(42)];
        source_allowlist.sort_unstable();
        PrivacyZkAcePolicyRecordV1::new(
            PrivacyPolicyIdV1::new(digest(43)),
            PrivacyZkAceIdentityCommitmentV1::new([u64::from(identity_seed) + 1; 6])
                .expect("small fixture words are canonical Goldilocks elements"),
            PrivacyPolicyDigestV1::new(digest(44)),
            epoch,
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("zkace").expect("asset name"),
            ),
            source_allowlist,
            lifecycle,
        )
        .expect("canonical ZK-ACE policy record")
    }
    fn bootle_lantern_public_matrix(seed: usize) -> BootleLanternIssuerPublicMatrixV1 {
        let first_column = core::array::from_fn(|block| BootleLanternPolynomialV1 {
            coefficients: (0..BOOTLE_LANTERN_RING_DEGREE_V1)
                .map(|coefficient| {
                    u16::try_from((block * 67 + coefficient + seed) % 12_288)
                        .expect("test residue fits u16")
                })
                .collect(),
        });
        BootleLanternIssuerPublicMatrixV1::from_r512_first_column_blocks_v1(&first_column)
            .expect("canonical degree-512 multiplication matrix")
    }
    fn bootle_lantern_policy() -> BootleLanternIssuerPolicyV1 {
        let allowed_values = (0..BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1)
            .map(|index| BootleLanternAllowedAttributeValuesV1 {
                values: if index == 1 {
                    vec![
                        BootleLanternAttributeValueV1::new([1; 8]),
                        BootleLanternAttributeValueV1::new([2; 8]),
                    ]
                } else {
                    Vec::new()
                },
            })
            .collect();
        let mut policy = BootleLanternIssuerPolicyV1 {
            issuer_id: PrivacyIssuerIdV1::new(digest(171)),
            policy_id: PrivacyPolicyIdV1::new(digest(172)),
            epoch: 1,
            lifecycle: BootleLanternIssuerPolicyLifecycleV1::Active,
            issuer_parameter_id: PrivacyParameterIdV1::new(digest(173)),
            issuer_parameter_digest: PrivacyParameterDigestV1::new([0; 32]),
            issuer_public_matrix: bootle_lantern_public_matrix(1),
            required_disclosure_bitmap: 0b0001_0010,
            allowed_values,
            record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]),
        };
        redigest_bootle_lantern_policy(&mut policy);
        policy
            .validate_initial()
            .expect("canonical initial Bootle/Lantern issuer policy");
        policy
    }
    fn redigest_bootle_lantern_policy(policy: &mut BootleLanternIssuerPolicyV1) {
        policy.issuer_parameter_digest = policy
            .computed_issuer_parameter_digest()
            .expect("canonical Bootle/Lantern issuer-parameter digest");
        policy.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        policy.record_digest = policy
            .computed_record_digest()
            .expect("canonical Bootle/Lantern issuer-policy digest");
    }
    fn rotated_bootle_lantern_policy(
        current: &BootleLanternIssuerPolicyV1,
    ) -> BootleLanternIssuerPolicyV1 {
        let mut successor = current.clone();
        successor.epoch += 1;
        successor.issuer_parameter_id = PrivacyParameterIdV1::new(digest(174));
        successor.issuer_public_matrix = bootle_lantern_public_matrix(701);
        redigest_bootle_lantern_policy(&mut successor);
        successor
            .validate_rotation_successor(current)
            .expect("canonical Bootle/Lantern issuer-policy rotation");
        successor
    }
    fn revoked_bootle_lantern_policy(
        current: &BootleLanternIssuerPolicyV1,
    ) -> BootleLanternIssuerPolicyV1 {
        let mut successor = current.clone();
        successor.epoch += 1;
        successor.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Revoked;
        redigest_bootle_lantern_policy(&mut successor);
        successor
            .validate_revocation_successor(current)
            .expect("canonical Bootle/Lantern issuer-policy revocation");
        successor
    }
    fn vega_issuer_record(
        epoch: u64,
        key_seed: u8,
        previous_record_digest: Option<PrivacyVegaIssuerRecordDigestV1>,
        lifecycle: PrivacyVegaIssuerRecordLifecycleV1,
    ) -> PrivacyVegaIssuerRecordV1 {
        PrivacyVegaIssuerRecordV1::new(
            PrivacyIssuerIdV1::new(digest(48)),
            epoch,
            p256_point(2, key_seed),
            crate::privacy::PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
            PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
            PrivacyVegaMdlDigestAlgorithmV1::Sha256,
            PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            previous_record_digest,
            lifecycle,
        )
        .expect("canonical Vega issuer record")
    }
    fn zk_x509_trust_anchor(
        epoch: u64,
        trust_store_seed: u8,
        ca_root_seed: u8,
        ca_root_epoch: u64,
        previous_record_digest: Option<PrivacyZkX509TrustAnchorRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509TrustAnchorRecordV1 {
        PrivacyZkX509TrustAnchorRecordV1::new(
            PrivacyIssuerIdV1::new(digest(50)),
            epoch,
            PrivacyX509TrustStoreDigestV1::new(digest(trust_store_seed)),
            PrivacyRootV1::new(digest(ca_root_seed)),
            ca_root_epoch,
            previous_record_digest,
            lifecycle,
        )
        .expect("canonical X.509 trust-anchor record")
    }
    fn revoked_zk_x509_trust_anchor(
        current: PrivacyZkX509TrustAnchorRecordV1,
    ) -> PrivacyZkX509TrustAnchorRecordV1 {
        PrivacyZkX509TrustAnchorRecordV1::new(
            current.trust_anchor_id,
            current.record_epoch + 1,
            current.trust_store_digest,
            current.ca_membership_root,
            current.ca_membership_root_epoch,
            Some(current.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        )
        .expect("canonical terminal X.509 trust-anchor record")
    }
    fn zk_x509_certificate_policy(
        epoch: u64,
        policy_seed: u8,
        previous_record_digest: Option<PrivacyZkX509CertificatePolicyRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509CertificatePolicyRecordV1 {
        PrivacyZkX509CertificatePolicyRecordV1::new(
            PrivacyIssuerIdV1::new(digest(50)),
            PrivacyPolicyIdV1::new(digest(51)),
            epoch,
            PrivacyPolicyDigestV1::new(digest(policy_seed)),
            PrivacyX509KeyUsageV1 {
                digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
                content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
            },
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            vec![0, 1, 3],
            previous_record_digest,
            lifecycle,
        )
        .expect("canonical X.509 certificate-policy record")
    }
    fn revoked_zk_x509_certificate_policy(
        current: &PrivacyZkX509CertificatePolicyRecordV1,
    ) -> PrivacyZkX509CertificatePolicyRecordV1 {
        PrivacyZkX509CertificatePolicyRecordV1::new(
            current.trust_anchor_id,
            current.policy_id,
            current.record_epoch + 1,
            current.policy_digest,
            current.required_key_usage,
            current.required_extended_key_usages.clone(),
            current.required_disclosed_attribute_indices.clone(),
            Some(current.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        )
        .expect("canonical terminal X.509 certificate-policy record")
    }
    fn zk_x509_crl(
        epoch: u64,
        crl_number: u64,
        crl_der_seed: u8,
        this_update_unix_seconds: u64,
        _revoked_root_seed: u8,
        previous_record_digest: Option<PrivacyZkX509CrlRecordDigestV1>,
    ) -> PrivacyZkX509CrlRecordV1 {
        PrivacyZkX509CrlRecordV1::new(
            PrivacyIssuerIdV1::new(digest(50)),
            PrivacyPolicyIdV1::new(digest(51)),
            epoch,
            crl_number,
            PrivacyX509CrlDerDigestV1::new(digest(crl_der_seed)),
            PrivacyX509CrlIssuerSpkiDigestV1::new(digest(52)),
            this_update_unix_seconds,
            this_update_unix_seconds + 300,
            previous_record_digest,
            PrivacyZkX509RecordLifecycleV1::Active,
        )
        .expect("canonical active X.509 signed-CRL record")
    }
    fn revoked_zk_x509_crl(current: PrivacyZkX509CrlRecordV1) -> PrivacyZkX509CrlRecordV1 {
        PrivacyZkX509CrlRecordV1::new(
            current.trust_anchor_id,
            current.certificate_policy_id,
            current.record_epoch + 1,
            current.crl_number,
            current.crl_der_digest,
            current.issuer_spki_digest,
            current.this_update_unix_seconds,
            current.next_update_unix_seconds,
            Some(current.record_digest),
            PrivacyZkX509RecordLifecycleV1::Revoked,
        )
        .expect("canonical terminal X.509 signed-CRL record")
    }
    macro_rules! for_each_privacy_isi_fixture {
        ($check:ident) => {
            $check!(
                RegisterPrivacyProtocolActivationV1::WIRE_ID,
                RegisterPrivacyProtocolActivationV1::new(activation())
            );
            $check!(SchedulePrivacyConsensusPolicyTighteningV1::WIRE_ID, {
                let mut next_limits = PrivacyConsensusLimitsV1::taira_default();
                next_limits.max_actions_per_block = 1;
                SchedulePrivacyConsensusPolicyTighteningV1::new(700, next_limits)
            });
            $check!(SchedulePrivacyProtocolLimitsTighteningV1::WIRE_ID, {
                let activation = activation();
                let mut next_limits = activation.protocol_limits;
                let PrivacyProtocolActivationLimitsV1::IrohaJindoPolynomialCommitmentV1(
                    ref mut limits,
                ) = next_limits
                else {
                    unreachable!("Jindo fixture")
                };
                limits.max_polynomial_count -= 1;
                SchedulePrivacyProtocolLimitsTighteningV1::new(
                    activation.protocol_id,
                    700,
                    next_limits,
                )
            });
            $check!(
                TransitionPrivacyProtocolLifecycleV1::WIRE_ID,
                TransitionPrivacyProtocolLifecycleV1::new(
                    PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
                    PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                        proposed_at_height: 100,
                        activated_at_height: 400,
                        state_since_height: 400,
                    }),
                )
            );
            $check!(
                PublishPrivacyRootV1::WIRE_ID,
                PublishPrivacyRootV1::new(publication())
            );
            $check!(
                BootstrapPrivacyOrchardPoolV1::WIRE_ID,
                BootstrapPrivacyOrchardPoolV1::new(orchard_bootstrap())
            );
            $check!(
                BootstrapPrivacyProofManagedPoolV1::WIRE_ID,
                BootstrapPrivacyProofManagedPoolV1::new(proof_managed_pool_bootstrap())
            );
            $check!(
                BootstrapPrivacyPgcAccountsV1::WIRE_ID,
                BootstrapPrivacyPgcAccountsV1::new(
                    pgc_bootstrap(),
                    PrivacyPgcBootstrapProofBytesV1::new(vec![0xA5, 0x5A, 1]),
                )
            );
            $check!(
                BootstrapPrivacyZkAmsRegistryV1::WIRE_ID,
                BootstrapPrivacyZkAmsRegistryV1::new(zk_ams_bootstrap())
            );
            $check!(
                RegisterPrivacyZkAcePolicyV1::WIRE_ID,
                RegisterPrivacyZkAcePolicyV1::new(zk_ace_policy(
                    1,
                    45,
                    PrivacyZkAcePolicyLifecycleV1::Active,
                ))
            );
            $check!(RotatePrivacyZkAcePolicyV1::WIRE_ID, {
                let current = zk_ace_policy(1, 45, PrivacyZkAcePolicyLifecycleV1::Active);
                let successor = zk_ace_policy(2, 46, PrivacyZkAcePolicyLifecycleV1::Active);
                RotatePrivacyZkAcePolicyV1::new(current.record_digest, successor)
            });
            $check!(RevokePrivacyZkAcePolicyV1::WIRE_ID, {
                let current = zk_ace_policy(1, 45, PrivacyZkAcePolicyLifecycleV1::Active);
                let successor = zk_ace_policy(2, 45, PrivacyZkAcePolicyLifecycleV1::Revoked);
                RevokePrivacyZkAcePolicyV1::new(current.record_digest, successor)
            });
            $check!(
                RegisterPrivacyBootleLanternIssuerPolicyV1::WIRE_ID,
                RegisterPrivacyBootleLanternIssuerPolicyV1::new(bootle_lantern_policy())
            );
            $check!(RotatePrivacyBootleLanternIssuerPolicyV1::WIRE_ID, {
                let current = bootle_lantern_policy();
                let successor = rotated_bootle_lantern_policy(&current);
                RotatePrivacyBootleLanternIssuerPolicyV1::new(current.record_digest, successor)
            });
            $check!(RevokePrivacyBootleLanternIssuerPolicyV1::WIRE_ID, {
                let current = bootle_lantern_policy();
                let successor = revoked_bootle_lantern_policy(&current);
                RevokePrivacyBootleLanternIssuerPolicyV1::new(current.record_digest, successor)
            });
            $check!(RegisterPrivacyVegaIssuerV1::WIRE_ID, {
                RegisterPrivacyVegaIssuerV1::new(vega_issuer_record(
                    1,
                    49,
                    None,
                    PrivacyVegaIssuerRecordLifecycleV1::Active,
                ))
            });
            $check!(RotatePrivacyVegaIssuerV1::WIRE_ID, {
                let current =
                    vega_issuer_record(1, 49, None, PrivacyVegaIssuerRecordLifecycleV1::Active);
                let successor = vega_issuer_record(
                    2,
                    50,
                    Some(current.record_digest),
                    PrivacyVegaIssuerRecordLifecycleV1::Active,
                );
                RotatePrivacyVegaIssuerV1::new(current.record_digest, successor)
            });
            $check!(RevokePrivacyVegaIssuerV1::WIRE_ID, {
                let current =
                    vega_issuer_record(1, 49, None, PrivacyVegaIssuerRecordLifecycleV1::Active);
                let successor = vega_issuer_record(
                    2,
                    49,
                    Some(current.record_digest),
                    PrivacyVegaIssuerRecordLifecycleV1::Revoked,
                );
                RevokePrivacyVegaIssuerV1::new(current.record_digest, successor)
            });
            $check!(
                RegisterPrivacyZkX509TrustAnchorV1::WIRE_ID,
                RegisterPrivacyZkX509TrustAnchorV1::new(zk_x509_trust_anchor(
                    1,
                    53,
                    54,
                    1,
                    None,
                    PrivacyZkX509RecordLifecycleV1::Active,
                ))
            );
            $check!(RotatePrivacyZkX509TrustAnchorV1::WIRE_ID, {
                let current = zk_x509_trust_anchor(
                    1,
                    53,
                    54,
                    1,
                    None,
                    PrivacyZkX509RecordLifecycleV1::Active,
                );
                let successor = zk_x509_trust_anchor(
                    2,
                    55,
                    56,
                    2,
                    Some(current.record_digest),
                    PrivacyZkX509RecordLifecycleV1::Active,
                );
                RotatePrivacyZkX509TrustAnchorV1::new(current.record_digest, successor)
            });
            $check!(RevokePrivacyZkX509TrustAnchorV1::WIRE_ID, {
                let current = zk_x509_trust_anchor(
                    1,
                    53,
                    54,
                    1,
                    None,
                    PrivacyZkX509RecordLifecycleV1::Active,
                );
                let successor = revoked_zk_x509_trust_anchor(current);
                RevokePrivacyZkX509TrustAnchorV1::new(
                    successor
                        .previous_record_digest
                        .expect("terminal record has predecessor"),
                    successor,
                )
            });
            $check!(
                RegisterPrivacyZkX509CertificatePolicyV1::WIRE_ID,
                RegisterPrivacyZkX509CertificatePolicyV1::new(zk_x509_certificate_policy(
                    1,
                    57,
                    None,
                    PrivacyZkX509RecordLifecycleV1::Active,
                ),)
            );
            $check!(RotatePrivacyZkX509CertificatePolicyV1::WIRE_ID, {
                let current =
                    zk_x509_certificate_policy(1, 57, None, PrivacyZkX509RecordLifecycleV1::Active);
                let successor = zk_x509_certificate_policy(
                    2,
                    58,
                    Some(current.record_digest),
                    PrivacyZkX509RecordLifecycleV1::Active,
                );
                RotatePrivacyZkX509CertificatePolicyV1::new(current.record_digest, successor)
            });
            $check!(RevokePrivacyZkX509CertificatePolicyV1::WIRE_ID, {
                let current =
                    zk_x509_certificate_policy(1, 57, None, PrivacyZkX509RecordLifecycleV1::Active);
                let successor = revoked_zk_x509_certificate_policy(&current);
                RevokePrivacyZkX509CertificatePolicyV1::new(current.record_digest, successor)
            });
            $check!(
                RegisterPrivacyZkX509CrlV1::WIRE_ID,
                RegisterPrivacyZkX509CrlV1::new(zk_x509_crl(1, 1, 59, 1_750_000_000, 60, None,))
            );
            $check!(RotatePrivacyZkX509CrlV1::WIRE_ID, {
                let current = zk_x509_crl(1, 1, 59, 1_750_000_000, 60, None);
                let successor =
                    zk_x509_crl(2, 2, 61, 1_750_000_060, 62, Some(current.record_digest));
                RotatePrivacyZkX509CrlV1::new(current.record_digest, successor)
            });
            $check!(RevokePrivacyZkX509CrlV1::WIRE_ID, {
                let current = zk_x509_crl(1, 1, 59, 1_750_000_000, 60, None);
                let successor = revoked_zk_x509_crl(current);
                RevokePrivacyZkX509CrlV1::new(
                    successor
                        .previous_record_digest
                        .expect("terminal record has predecessor"),
                    successor,
                )
            });
            $check!(
                SubmitPrivacyProofV1::WIRE_ID,
                SubmitPrivacyProofV1::new(envelope())
            );
        };
    }
    fn assert_slice_roundtrip<T>(wire_id: &str, value: T)
    where
        T: Clone
            + core::fmt::Debug
            + PartialEq
            + norito::codec::Encode
            + for<'a> DecodeFromSlice<'a>,
    {
        let bytes = value.encode();
        let (decoded, used) = T::decode_from_slice(&bytes).expect("decode");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, value, "{wire_id} direct slice roundtrip");
    }
    fn assert_slice_rejects_malformed<T>(wire_id: &str, value: T)
    where
        T: norito::codec::Encode + for<'a> DecodeFromSlice<'a>,
    {
        let bytes = value.encode();
        for truncated_len in 0..bytes.len() {
            assert!(
                T::decode_from_slice(&bytes[..truncated_len]).is_err(),
                "{wire_id} accepted a {truncated_len}-byte truncation of {} bytes",
                bytes.len()
            );
        }
        for suffix in [
            &[0x00][..],
            &[0xA5][..],
            &[0xFF, 0x00, 0xFF][..],
            &[0x00; 8][..],
        ] {
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(suffix);
            assert!(
                T::decode_from_slice(&trailing).is_err(),
                "{wire_id} accepted {} trailing byte(s)",
                suffix.len()
            );
        }
    }
    #[test]
    fn privacy_isis_roundtrip_through_direct_slice_decoders() {
        let mut fixture_count = 0_usize;
        macro_rules! check {
            ($wire_id:expr, $value:expr) => {{
                fixture_count += 1;
                assert_slice_roundtrip($wire_id, $value);
            }};
        }
        for_each_privacy_isi_fixture!(check);
        // The full qualification record has its canonical roundtrip coverage in
        // `privacy::tests::release_manifest`; do not duplicate that large fixture here.
        assert_eq!(fixture_count + 1, PRIVACY_ISI_WIRE_IDS_V1.len());
    }
    #[test]
    fn privacy_isi_decoders_reject_trailing_and_truncated_payloads() {
        let mut fixture_count = 0_usize;
        macro_rules! check {
            ($wire_id:expr, $value:expr) => {{
                fixture_count += 1;
                assert_slice_rejects_malformed($wire_id, $value);
            }};
        }
        for_each_privacy_isi_fixture!(check);
        // The full qualification record's malformed-wire coverage lives with
        // the release/deployment manifest fixture.
        assert_eq!(fixture_count + 1, PRIVACY_ISI_WIRE_IDS_V1.len());
        assert!(
            BootstrapPrivacyPgcAccountsV1::decode_from_slice(&pgc_bootstrap().encode()).is_err(),
            "the unreleased proofless bootstrap layout has no legacy decoder"
        );
    }

    #[test]
    fn bootle_lantern_governance_isi_json_is_closed() {
        macro_rules! assert_closed_json {
            ($instruction_type:ty, $instruction:expr) => {{
                let instruction: $instruction_type = $instruction;
                let canonical = norito::json::to_json(&instruction)
                    .expect("canonical Bootle/Lantern governance instruction JSON encodes");
                assert_eq!(
                    norito::json::from_json::<$instruction_type>(&canonical)
                        .expect("canonical Bootle/Lantern governance instruction JSON decodes"),
                    instruction
                );
                let hostile = canonical.replacen('{', "{\"adversarial_extension\":null,", 1);
                assert_ne!(hostile, canonical);
                assert!(
                    norito::json::from_json::<$instruction_type>(&hostile).is_err(),
                    "Bootle/Lantern governance instruction JSON must reject unknown fields"
                );
            }};
        }
        let current = bootle_lantern_policy();
        assert_closed_json!(
            RegisterPrivacyBootleLanternIssuerPolicyV1,
            RegisterPrivacyBootleLanternIssuerPolicyV1::new(current.clone())
        );
        assert_closed_json!(
            RotatePrivacyBootleLanternIssuerPolicyV1,
            RotatePrivacyBootleLanternIssuerPolicyV1::new(
                current.record_digest,
                rotated_bootle_lantern_policy(&current),
            )
        );
        assert_closed_json!(
            RevokePrivacyBootleLanternIssuerPolicyV1,
            RevokePrivacyBootleLanternIssuerPolicyV1::new(
                current.record_digest,
                revoked_bootle_lantern_policy(&current),
            )
        );
    }
    #[test]
    fn stable_wire_ids_have_no_retired_compatibility_names() {
        assert_eq!(PRIVACY_ISI_WIRE_IDS_V1.len(), 29);
        let mut sorted_wire_ids = PRIVACY_ISI_WIRE_IDS_V1;
        sorted_wire_ids.sort_unstable();
        assert!(
            sorted_wire_ids.windows(2).all(|pair| pair[0] != pair[1]),
            "all 29 canonical first-release privacy ISIs must have unique wire IDs"
        );
        for wire_id in PRIVACY_ISI_WIRE_IDS_V1 {
            assert!(wire_id.starts_with("iroha.privacy."));
            assert!(matches!(wire_id.rsplit_once('.'), Some((_, "v1"))));
            assert!(!wire_id.contains("zkAt"));
            assert!(!wire_id.contains("silent"));
            assert!(!wire_id.contains("penumbra"));
            assert!(!wire_id.contains("aztec"));
        }
    }
}
