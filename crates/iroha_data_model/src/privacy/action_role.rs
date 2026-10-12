//! Closed Exact12 action roles and the one canonical proof-envelope binding.
//!
//! A role is the unit of native dispatch: one typed statement shape, one typed
//! proof shape, one native verifier and one ledger-effect executor. The twelve
//! registered protocols give thirteen roles because ZK-AMS carries two actions.
//! Naming a role says only that its types exist. Whether a verifier is
//! implemented, whether an effect is applied and whether the operation is
//! delivered are separate facts owned by the Core dispatch registry
//! (`iroha_core_privacy::privacy_dispatch`).
//!
//! [`PrivacyProofEnvelopeV1::bind_v1`] is the only assembler of an envelope:
//! every redundant field is derived from the typed statement, so a builder
//! cannot pair a statement with another protocol, proof system, engine, digest
//! or role. [`PrivacyProofEnvelopeV1::action_role_v1`] is the only resolver of
//! the role of a received envelope; intrinsic envelope validation and Core
//! admission both use it.

use core::fmt;

use super::{
    IrohaZkAmsProofV1, PrivacyExact12CatalogCommitmentV1, PrivacyProofEnvelopeV1,
    PrivacyProofEnvelopeValidationError, PrivacyProofV1, PrivacyProofWireMagicV1,
    PrivacyProtocolIdV1, PrivacyStatementV1, PrivacyZkAmsActionV1,
};

/// Closed action role selected by one Exact12 proof envelope.
///
/// The order is the canonical protocol order of [`PrivacyProtocolIdV1::ALL`],
/// with the two ZK-AMS actions in their statement-variant order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrivacyActionRoleV1 {
    /// ZK-ACE authorization of one transparent asset transfer.
    ZkAceAuthorization,
    /// Anonymous PGC k-out-of-n payment over the encrypted account table.
    AnonymousPgcPayment,
    /// `VeRange` aggregated range component.
    VeRangeRange,
    /// ZK-AMS batch admission into the account registry.
    ZkAmsBatchAdmission,
    /// ZK-AMS anonymous account provisioning.
    ZkAmsProvisionAccount,
    /// Vega presentation of an existing credential.
    VegaCredentialPresentation,
    /// ZK-X509 certificate presentation.
    ZkX509CertificatePresentation,
    /// Jindo batched polynomial evaluation.
    JindoBatchedEvaluation,
    /// Bootle/Lantern anonymous-credential presentation.
    BootleLanternPresentation,
    /// Orchard action bundle.
    OrchardActions,
    /// Monero FCMP++ transfer.
    FcmpTransfer,
    /// IVM private-note transition.
    IvmPrivateNoteTransition,
    /// PQ-MASP transition.
    PqMaspTransition,
}

impl PrivacyActionRoleV1 {
    /// Number of roles in the closed first-release registry.
    pub const COUNT: usize = 13;
    /// Every role in canonical order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::ZkAceAuthorization,
        Self::AnonymousPgcPayment,
        Self::VeRangeRange,
        Self::ZkAmsBatchAdmission,
        Self::ZkAmsProvisionAccount,
        Self::VegaCredentialPresentation,
        Self::ZkX509CertificatePresentation,
        Self::JindoBatchedEvaluation,
        Self::BootleLanternPresentation,
        Self::OrchardActions,
        Self::FcmpTransfer,
        Self::IvmPrivateNoteTransition,
        Self::PqMaspTransition,
    ];

    /// The one registered protocol this role belongs to.
    #[must_use]
    pub const fn protocol_id(self) -> PrivacyProtocolIdV1 {
        match self {
            Self::ZkAceAuthorization => PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
            Self::AnonymousPgcPayment => PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            Self::VeRangeRange => PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
            Self::ZkAmsBatchAdmission | Self::ZkAmsProvisionAccount => {
                PrivacyProtocolIdV1::IrohaZkAmsV1
            }
            Self::VegaCredentialPresentation => PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            Self::ZkX509CertificatePresentation => PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            Self::JindoBatchedEvaluation => PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
            Self::BootleLanternPresentation => PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
            Self::OrchardActions => PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            Self::FcmpTransfer => PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
            Self::IvmPrivateNoteTransition => PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            Self::PqMaspTransition => PrivacyProtocolIdV1::PqMaspStarkV1,
        }
    }

    /// Stable diagnostic label of this role.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::ZkAceAuthorization => "zk-ace-authorization",
            Self::AnonymousPgcPayment => "anonymous-pgc-payment",
            Self::VeRangeRange => "verange-range",
            Self::ZkAmsBatchAdmission => "zk-ams-batch-admission",
            Self::ZkAmsProvisionAccount => "zk-ams-provision-account",
            Self::VegaCredentialPresentation => "vega-credential-presentation",
            Self::ZkX509CertificatePresentation => "zk-x509-certificate-presentation",
            Self::JindoBatchedEvaluation => "jindo-batched-evaluation",
            Self::BootleLanternPresentation => "bootle-lantern-presentation",
            Self::OrchardActions => "orchard-actions",
            Self::FcmpTransfer => "fcmp-transfer",
            Self::IvmPrivateNoteTransition => "ivm-private-note-transition",
            Self::PqMaspTransition => "pq-masp-transition",
        }
    }
}

impl fmt::Display for PrivacyActionRoleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_label())
    }
}

impl PrivacyProtocolIdV1 {
    /// Every role this protocol carries, in canonical order.
    #[must_use]
    pub const fn action_roles_v1(self) -> &'static [PrivacyActionRoleV1] {
        match self {
            Self::ZkAcePqAuthorizationV1 => &[PrivacyActionRoleV1::ZkAceAuthorization],
            Self::AnonymousPgcKOutOfNV1 => &[PrivacyActionRoleV1::AnonymousPgcPayment],
            Self::VeRangeTransparentRangeV1 => &[PrivacyActionRoleV1::VeRangeRange],
            Self::IrohaZkAmsV1 => &[
                PrivacyActionRoleV1::ZkAmsBatchAdmission,
                PrivacyActionRoleV1::ZkAmsProvisionAccount,
            ],
            Self::VegaExistingCredentialZkV1 => &[PrivacyActionRoleV1::VegaCredentialPresentation],
            Self::IrohaZkX509StarkP256V1 => &[PrivacyActionRoleV1::ZkX509CertificatePresentation],
            Self::IrohaJindoPolynomialCommitmentV1 => {
                &[PrivacyActionRoleV1::JindoBatchedEvaluation]
            }
            Self::IrohaBootleLanternAnoncredV1 => &[PrivacyActionRoleV1::BootleLanternPresentation],
            Self::OrchardHalo2ActionsV1 => &[PrivacyActionRoleV1::OrchardActions],
            Self::MoneroFcmpPlusPlusV1 => &[PrivacyActionRoleV1::FcmpTransfer],
            Self::IrohaIvmPrivateNoteStarkV1 => &[PrivacyActionRoleV1::IvmPrivateNoteTransition],
            Self::PqMaspStarkV1 => &[PrivacyActionRoleV1::PqMaspTransition],
        }
    }
}

impl PrivacyStatementV1 {
    /// The one role this typed statement selects.
    #[must_use]
    pub const fn action_role_v1(&self) -> PrivacyActionRoleV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(_) => PrivacyActionRoleV1::ZkAceAuthorization,
            Self::AnonymousPgcKOutOfNV1(_) => PrivacyActionRoleV1::AnonymousPgcPayment,
            Self::VeRangeTransparentRangeV1(_) => PrivacyActionRoleV1::VeRangeRange,
            Self::IrohaZkAmsV1(statement) => match &statement.action {
                PrivacyZkAmsActionV1::BatchAdmission(_) => PrivacyActionRoleV1::ZkAmsBatchAdmission,
                PrivacyZkAmsActionV1::ProvisionAccount(_) => {
                    PrivacyActionRoleV1::ZkAmsProvisionAccount
                }
            },
            Self::VegaExistingCredentialZkV1(_) => PrivacyActionRoleV1::VegaCredentialPresentation,
            Self::IrohaZkX509StarkP256V1(_) => PrivacyActionRoleV1::ZkX509CertificatePresentation,
            Self::IrohaJindoPolynomialCommitmentV1(_) => {
                PrivacyActionRoleV1::JindoBatchedEvaluation
            }
            Self::IrohaBootleLanternAnoncredV1(_) => PrivacyActionRoleV1::BootleLanternPresentation,
            Self::OrchardHalo2ActionsV1(_) => PrivacyActionRoleV1::OrchardActions,
            Self::MoneroFcmpPlusPlusV1(_) => PrivacyActionRoleV1::FcmpTransfer,
            Self::IrohaIvmPrivateNoteStarkV1(_) => PrivacyActionRoleV1::IvmPrivateNoteTransition,
            Self::PqMaspStarkV1(_) => PrivacyActionRoleV1::PqMaspTransition,
        }
    }
}

impl PrivacyProofV1 {
    /// The one role this typed proof payload can discharge.
    #[must_use]
    pub const fn action_role_v1(&self) -> PrivacyActionRoleV1 {
        match self {
            Self::ZkAcePqAuthorizationV1(_) => PrivacyActionRoleV1::ZkAceAuthorization,
            Self::AnonymousPgcKOutOfNV1(_) => PrivacyActionRoleV1::AnonymousPgcPayment,
            Self::VeRangeTransparentRangeV1(_) => PrivacyActionRoleV1::VeRangeRange,
            Self::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(_)) => {
                PrivacyActionRoleV1::ZkAmsBatchAdmission
            }
            Self::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(_)) => {
                PrivacyActionRoleV1::ZkAmsProvisionAccount
            }
            Self::VegaExistingCredentialZkV1(_) => PrivacyActionRoleV1::VegaCredentialPresentation,
            Self::IrohaZkX509StarkP256V1(_) => PrivacyActionRoleV1::ZkX509CertificatePresentation,
            Self::IrohaJindoPolynomialCommitmentV1(_) => {
                PrivacyActionRoleV1::JindoBatchedEvaluation
            }
            Self::IrohaBootleLanternAnoncredV1(_) => PrivacyActionRoleV1::BootleLanternPresentation,
            Self::OrchardHalo2ActionsV1(_) => PrivacyActionRoleV1::OrchardActions,
            Self::MoneroFcmpPlusPlusV1(_) => PrivacyActionRoleV1::FcmpTransfer,
            Self::IrohaIvmPrivateNoteStarkV1(_) => PrivacyActionRoleV1::IvmPrivateNoteTransition,
            Self::PqMaspStarkV1(_) => PrivacyActionRoleV1::PqMaspTransition,
        }
    }
}

impl PrivacyProofEnvelopeV1 {
    /// Assemble the one canonical envelope for a typed statement and its proof.
    ///
    /// The protocol, proof system and engine come from the statement variant,
    /// the five artifact identities from the statement context and the
    /// statement digest from the canonical statement bytes. This is the only
    /// place an envelope is assembled; protocol builders supply the statement
    /// and the proof and nothing else. Proof bytes are not inspected, so a
    /// builder may bind the empty proof it uses to derive a transaction intent.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyProofEnvelopeValidationError::EncodingFailure`] when the
    /// statement has no canonical digest, and the role-resolution error of
    /// [`Self::action_role_v1`] when the proof belongs to another protocol or
    /// to the other ZK-AMS action.
    pub fn bind_v1(
        statement: PrivacyStatementV1,
        proof: PrivacyProofV1,
    ) -> Result<Self, PrivacyProofEnvelopeValidationError> {
        let protocol_id = statement.protocol_id();
        let context = *statement.context();
        let statement_digest = statement
            .digest()
            .map_err(|_| PrivacyProofEnvelopeValidationError::EncodingFailure)?;
        let envelope = Self {
            wire_magic: PrivacyProofWireMagicV1::canonical(),
            catalog_commitment: PrivacyExact12CatalogCommitmentV1::canonical(),
            protocol_id,
            proof_system_id: protocol_id.expected_proof_system(),
            engine_id: protocol_id.expected_engine(),
            parameter_id: context.parameter_id,
            parameter_digest: context.parameter_digest,
            verifier_digest: context.verifier_digest,
            statement_schema_digest: context.statement_schema_digest,
            engine_manifest_digest: context.engine_manifest_digest,
            statement_digest,
            statement,
            proof,
        };
        envelope.action_role_v1()?;
        Ok(envelope)
    }

    /// Resolve the single role this envelope selects.
    ///
    /// The envelope protocol, the statement variant and the proof variant must
    /// name one protocol, and a ZK-AMS proof must be the variant of its
    /// statement's action. Every native dispatch decision is made from the
    /// returned role, so no second routing key can disagree with it.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`PrivacyProofEnvelopeValidationError::StatementProtocolMismatch`],
    /// [`PrivacyProofEnvelopeValidationError::ProofProtocolMismatch`] or
    /// [`PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch`] for the
    /// first substitution in that order.
    pub fn action_role_v1(
        &self,
    ) -> Result<PrivacyActionRoleV1, PrivacyProofEnvelopeValidationError> {
        let statement_protocol = self.statement.protocol_id();
        if statement_protocol != self.protocol_id {
            return Err(
                PrivacyProofEnvelopeValidationError::StatementProtocolMismatch {
                    envelope: self.protocol_id,
                    statement: statement_protocol,
                },
            );
        }
        let proof_protocol = self.proof.protocol_id();
        if proof_protocol != self.protocol_id {
            return Err(PrivacyProofEnvelopeValidationError::ProofProtocolMismatch {
                envelope: self.protocol_id,
                proof: proof_protocol,
            });
        }
        let role = self.statement.action_role_v1();
        if self.proof.action_role_v1() != role {
            // Both variants name one protocol here, so only the two ZK-AMS
            // actions can still disagree.
            return Err(PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch);
        }
        Ok(role)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::privacy::{
        PrivacyConsensusLimitsV1, PrivacyProofValidationError, privacy_action_role_samples_v1,
    };

    /// One structurally valid statement and proof for each of the thirteen roles.
    fn role_samples() -> Vec<(PrivacyActionRoleV1, PrivacyStatementV1, PrivacyProofV1)> {
        privacy_action_role_samples_v1()
            .expect("role samples")
            .into_iter()
            .map(|sample| {
                (
                    sample.role,
                    sample.envelope.statement,
                    sample.envelope.proof,
                )
            })
            .collect()
    }

    #[test]
    fn role_samples_cover_every_role_and_pass_activation_validation() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let samples = privacy_action_role_samples_v1().expect("role samples");
        assert_eq!(
            samples.iter().map(|sample| sample.role).collect::<Vec<_>>(),
            PrivacyActionRoleV1::ALL
        );
        for sample in samples {
            assert_eq!(sample.envelope.action_role_v1(), Ok(sample.role));
            sample
                .activation
                .validate()
                .expect("valid sample activation");
            sample
                .envelope
                .validate_against_activation(&sample.activation, &limits, 2)
                .expect("the sample is admitted by its activation");
            assert!(
                sample
                    .envelope
                    .validate_against_activation(&sample.activation, &limits, 1)
                    .is_err(),
                "the sample activation is not effective before height 2"
            );
        }
    }

    #[test]
    fn roles_are_closed_ordered_and_cover_every_protocol() {
        assert_eq!(PrivacyActionRoleV1::ALL.len(), PrivacyActionRoleV1::COUNT);
        let mut sorted = PrivacyActionRoleV1::ALL;
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            PrivacyActionRoleV1::ALL,
            "ALL is in declaration order"
        );
        let labels = PrivacyActionRoleV1::ALL
            .iter()
            .map(|role| role.canonical_label())
            .collect::<BTreeSet<_>>();
        assert_eq!(labels.len(), PrivacyActionRoleV1::COUNT);
        for role in PrivacyActionRoleV1::ALL {
            assert_eq!(role.to_string(), role.canonical_label());
        }
        let mut from_protocols = Vec::new();
        for protocol in PrivacyProtocolIdV1::ALL {
            let roles = protocol.action_roles_v1();
            assert!(!roles.is_empty(), "{protocol:?} carries at least one role");
            for role in roles {
                assert_eq!(role.protocol_id(), protocol);
                from_protocols.push(*role);
            }
        }
        assert_eq!(from_protocols, PrivacyActionRoleV1::ALL);
        assert_eq!(
            PrivacyProtocolIdV1::IrohaZkAmsV1.action_roles_v1(),
            [
                PrivacyActionRoleV1::ZkAmsBatchAdmission,
                PrivacyActionRoleV1::ZkAmsProvisionAccount
            ]
        );
    }

    #[test]
    fn statement_proof_and_envelope_resolve_one_role_for_every_role() {
        let samples = role_samples();
        assert_eq!(
            samples.iter().map(|(role, _, _)| *role).collect::<Vec<_>>(),
            PrivacyActionRoleV1::ALL
        );
        for (role, statement, proof) in samples {
            assert_eq!(statement.action_role_v1(), role);
            assert_eq!(proof.action_role_v1(), role);
            assert_eq!(role.protocol_id(), statement.protocol_id());
            assert_eq!(role.protocol_id(), proof.protocol_id());
            let envelope = PrivacyProofEnvelopeV1::bind_v1(statement, proof).expect("bind");
            assert_eq!(envelope.action_role_v1(), Ok(role));
        }
    }

    #[test]
    fn bind_v1_derives_every_redundant_field_from_the_statement() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        for (role, statement, proof) in role_samples() {
            let envelope = PrivacyProofEnvelopeV1::bind_v1(statement.clone(), proof.clone())
                .expect("canonical envelope");
            let protocol = role.protocol_id();
            let context = statement.context();
            assert_eq!(envelope.wire_magic, PrivacyProofWireMagicV1::canonical());
            assert_eq!(
                envelope.catalog_commitment,
                PrivacyExact12CatalogCommitmentV1::canonical()
            );
            assert_eq!(envelope.protocol_id, protocol);
            assert_eq!(envelope.proof_system_id, protocol.expected_proof_system());
            assert_eq!(envelope.engine_id, protocol.expected_engine());
            assert_eq!(envelope.parameter_id, context.parameter_id);
            assert_eq!(envelope.parameter_digest, context.parameter_digest);
            assert_eq!(envelope.verifier_digest, context.verifier_digest);
            assert_eq!(
                envelope.statement_schema_digest,
                context.statement_schema_digest
            );
            assert_eq!(
                envelope.engine_manifest_digest,
                context.engine_manifest_digest
            );
            assert_eq!(
                envelope.statement_digest,
                statement.digest().expect("statement digest")
            );
            assert_eq!(envelope.statement, statement);
            assert_eq!(envelope.proof, proof);
            envelope
                .validate_with_limits(&limits)
                .expect("the canonical envelope is intrinsically valid");
        }
    }

    /// A proof-free envelope can be bound to derive a transaction intent, and
    /// it is never an admissible envelope.
    #[test]
    fn bind_v1_binds_the_empty_intent_projection_without_making_it_admissible() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        for (role, statement, mut proof) in role_samples() {
            proof.bytes_mut().bytes.clear();
            let envelope =
                PrivacyProofEnvelopeV1::bind_v1(statement, proof).expect("projection envelope");
            assert_eq!(envelope.action_role_v1(), Ok(role));
            assert!(envelope.proof.bytes().as_bytes().is_empty());
            assert_eq!(
                envelope.validate_with_limits(&limits),
                Err(PrivacyProofEnvelopeValidationError::Proof(
                    PrivacyProofValidationError::Empty
                ))
            );
        }
    }

    #[test]
    fn bind_v1_rejects_a_proof_of_any_other_role() {
        let samples = role_samples();
        for (role, statement, _) in &samples {
            for (other_role, _, other_proof) in &samples {
                if other_role == role {
                    continue;
                }
                let error = PrivacyProofEnvelopeV1::bind_v1(statement.clone(), other_proof.clone())
                    .expect_err("a proof of another role cannot be bound");
                if other_role.protocol_id() == role.protocol_id() {
                    assert_eq!(
                        error,
                        PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch
                    );
                } else {
                    assert_eq!(
                        error,
                        PrivacyProofEnvelopeValidationError::ProofProtocolMismatch {
                            envelope: role.protocol_id(),
                            proof: other_role.protocol_id(),
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn role_resolution_rejects_protocol_statement_and_proof_substitution() {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let samples = role_samples();
        let envelopes = samples
            .iter()
            .map(|(role, statement, proof)| {
                (
                    *role,
                    PrivacyProofEnvelopeV1::bind_v1(statement.clone(), proof.clone())
                        .expect("canonical envelope"),
                )
            })
            .collect::<Vec<_>>();
        for (role, envelope) in &envelopes {
            for (other_role, other) in &envelopes {
                if other_role == role {
                    continue;
                }
                let same_protocol = other_role.protocol_id() == role.protocol_id();

                // Another protocol identity over the same statement and proof.
                if !same_protocol {
                    let mut relabelled = envelope.clone();
                    relabelled.protocol_id = other.protocol_id;
                    relabelled.proof_system_id = other.proof_system_id;
                    relabelled.engine_id = other.engine_id;
                    assert_eq!(
                        relabelled.action_role_v1(),
                        Err(
                            PrivacyProofEnvelopeValidationError::StatementProtocolMismatch {
                                envelope: other.protocol_id,
                                statement: role.protocol_id(),
                            }
                        )
                    );
                    assert!(relabelled.validate_with_limits(&limits).is_err());
                }

                // Another role's statement under this envelope and proof.
                let mut statement_swapped = envelope.clone();
                statement_swapped.statement = other.statement.clone();
                statement_swapped.statement_digest = other.statement_digest;
                let expected = if same_protocol {
                    PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch
                } else {
                    PrivacyProofEnvelopeValidationError::StatementProtocolMismatch {
                        envelope: role.protocol_id(),
                        statement: other_role.protocol_id(),
                    }
                };
                assert_eq!(statement_swapped.action_role_v1(), Err(expected));
                assert!(statement_swapped.validate_with_limits(&limits).is_err());

                // Another role's proof under this envelope and statement.
                let mut proof_swapped = envelope.clone();
                proof_swapped.proof = other.proof.clone();
                let expected = if same_protocol {
                    PrivacyProofEnvelopeValidationError::ZkAmsActionProofMismatch
                } else {
                    PrivacyProofEnvelopeValidationError::ProofProtocolMismatch {
                        envelope: role.protocol_id(),
                        proof: other_role.protocol_id(),
                    }
                };
                assert_eq!(proof_swapped.action_role_v1(), Err(expected));
                assert!(proof_swapped.validate_with_limits(&limits).is_err());
            }
        }
    }
}
