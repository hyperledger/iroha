//! Typed Exact12 dispatch registry: one native verifier and one ledger effect per role.
//!
//! [`PRIVACY_ROLE_DISPATCH_TABLE_V1`] has one row for each
//! [`PrivacyActionRoleV1`]. A row keeps four facts apart:
//!
//! * presence: the role is a variant of the closed enum and has a row here;
//! * verification: [`PrivacyRoleVerificationV1`] says whether the single
//!   verifier dispatch runs a native verifier for the role or refuses it with a
//!   concrete [`PrivacyRoleLimitationV1`];
//! * state effects: [`PrivacyRoleEffectClassV1`] names the one ledger-effect
//!   class the verifier may hand to the single state executor, and
//!   [`PrivacyRoleDispatchRowV1::state_effects`] says whether that effect
//!   can be reached at all;
//! * delivery: [`PrivacyRoleDeliveryV1`] says whether the complete
//!   operation (typed instruction, contract binding, SDK operation, fixtures,
//!   multi-validator flow, restart and replay) is delivered. No role is.
//!
//! `Implemented` verification means that a compiled native verifier is
//! dispatched. It is not a soundness, zero-knowledge or deployment claim.
//!
//! The registry is the definition of dispatch support. It is deliberately not
//! derived from the compiled-profile catalog
//! ([`crate::privacy_profiles::compiled_privacy_profile_v1`]), which also
//! encodes release readiness and profile-initialization results. A test pins
//! that both describe the same refusals today; a product task that completes a
//! verifier changes its row here together with the engine.
//!
//! The single dispatch (`crate::privacy_verifier::verify_privacy_envelope_v1`)
//! consults [`require_supported_privacy_action_role_v1`] immediately before
//! the native verifier and seals an effect only when
//! [`VerifiedPrivacyLedgerEffectsV1::discharges_role_v1`] holds, so a refused
//! role returns a typed error and an effect of another role cannot leave the
//! verifier.

use iroha_data_model::privacy::{PrivacyActionRoleV1, PrivacyProtocolIdV1};
use thiserror::Error;

use crate::privacy_verifier::{
    VerifiedPrivacyLedgerEffectsV1, VerifiedProofManagedPoolTransitionV1,
};

/// Concrete technical limitation that leaves a role without usable verification.
///
/// Each variant names missing construction work, never an approval, a
/// qualification record or an activation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyRoleLimitationV1 {
    /// ZK-ACE: the dedicated STARK has no completed Fiat--Shamir reduction in
    /// the quantum random-oracle model and no multi-target accounting for its
    /// hashes. Its native prover and verifier refuse every input.
    ZkAceSoundnessDerivationIncomplete,
    /// ZK-AMS: the production source replay and the composite multi-key
    /// homomorphic admission verifier are incomplete.
    ZkAmsCompositeVerifierIncomplete,
    /// Vega: no complete Figure 9 relation with its fixed proving and
    /// verifying keys is compiled.
    VegaFigure9RelationIncomplete,
    /// ZK-X509: the bounded joint certificate relation, its soundness
    /// analysis and its maximum-proof resource bounds are incomplete.
    ZkX509JointRelationIncomplete,
    /// The native engine of the role is not compiled into this build.
    NativeEngineNotCompiled,
}

impl PrivacyRoleLimitationV1 {
    /// One-sentence description used by the typed refusal.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ZkAceSoundnessDerivationIncomplete => {
                "the ZK-ACE STARK has no completed qROM soundness derivation"
            }
            Self::ZkAmsCompositeVerifierIncomplete => {
                "the ZK-AMS source replay and composite admission verifier are incomplete"
            }
            Self::VegaFigure9RelationIncomplete => {
                "no complete Vega Figure 9 relation with fixed keys is compiled"
            }
            Self::ZkX509JointRelationIncomplete => {
                "the bounded joint ZK-X509 relation and its resource bounds are incomplete"
            }
            Self::NativeEngineNotCompiled => "the native engine is not compiled into this build",
        }
    }
}

impl core::fmt::Display for PrivacyRoleLimitationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.description())
    }
}

/// Whether the single dispatch runs a native verifier for a role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyRoleVerificationV1 {
    /// A compiled native verifier is dispatched for the role.
    Implemented,
    /// The dispatch refuses the role before any proof byte is examined.
    Unsupported(PrivacyRoleLimitationV1),
}

/// The one ledger-effect class a role's verifier hands to the state executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyRoleEffectClassV1 {
    /// Verification only: the action budget is charged and nothing else is written.
    VerifyOnly,
    /// Complete Anonymous-PGC encrypted account-table transition.
    AnonymousPgcPayment,
    /// Orchard nullifier, frontier, root and public-bridge transition.
    OrchardActions,
    /// FCMP++, private-IVM or PQ-MASP nullifier, commitment and root transition.
    ProofManagedPool,
    /// ZK-AMS admission anchors and account-registry successor.
    ZkAmsBatchAdmission,
    /// ZK-AMS provisioning key image and fresh account.
    ZkAmsProvisionAccount,
    /// ZK-ACE replay marker and transparent asset transfer.
    ZkAceAuthorization,
    /// ZK-X509 policy-scoped certificate nullifier.
    ZkX509Certificate,
}

/// Whether the ledger effect of a role can be reached through the dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyRoleStateEffectsV1 {
    /// The role is verified and writes nothing beyond its action-budget charge.
    VerifyOnly,
    /// The role is verified and its effect class is applied by the state executor.
    Applied,
    /// Verification is unsupported, so no effect of the role can be reached.
    Unreachable,
}

/// Whether the complete operation of a role is delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyRoleDeliveryV1 {
    /// The typed instruction, contract binding, SDK operation, fixtures,
    /// multi-validator flow, restart and replay are not all present.
    NotDelivered,
    /// Every part of the operation is present and exercised.
    Delivered,
}

/// One row of the typed Exact12 dispatch registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyRoleDispatchRowV1 {
    /// The role this row describes.
    pub role: PrivacyActionRoleV1,
    /// Whether the single dispatch verifies the role.
    pub verification: PrivacyRoleVerificationV1,
    /// The only ledger-effect class the role's verifier may produce.
    pub effect_class: PrivacyRoleEffectClassV1,
    /// Whether the complete operation is delivered.
    pub delivery: PrivacyRoleDeliveryV1,
}

impl PrivacyRoleDispatchRowV1 {
    /// The registered protocol of this row's role.
    #[must_use]
    pub const fn protocol_id(&self) -> PrivacyProtocolIdV1 {
        self.role.protocol_id()
    }

    /// Whether the ledger effect of this role can be reached.
    #[must_use]
    pub const fn state_effects(&self) -> PrivacyRoleStateEffectsV1 {
        match (self.verification, self.effect_class) {
            (PrivacyRoleVerificationV1::Unsupported(_), _) => {
                PrivacyRoleStateEffectsV1::Unreachable
            }
            (PrivacyRoleVerificationV1::Implemented, PrivacyRoleEffectClassV1::VerifyOnly) => {
                PrivacyRoleStateEffectsV1::VerifyOnly
            }
            (PrivacyRoleVerificationV1::Implemented, _) => PrivacyRoleStateEffectsV1::Applied,
        }
    }
}

const fn row(
    role: PrivacyActionRoleV1,
    verification: PrivacyRoleVerificationV1,
    effect_class: PrivacyRoleEffectClassV1,
) -> PrivacyRoleDispatchRowV1 {
    PrivacyRoleDispatchRowV1 {
        role,
        verification,
        effect_class,
        delivery: PrivacyRoleDeliveryV1::NotDelivered,
    }
}

const IMPLEMENTED: PrivacyRoleVerificationV1 = PrivacyRoleVerificationV1::Implemented;

const fn unsupported(limitation: PrivacyRoleLimitationV1) -> PrivacyRoleVerificationV1 {
    PrivacyRoleVerificationV1::Unsupported(limitation)
}

/// The typed Exact12 dispatch registry in [`PrivacyActionRoleV1::ALL`] order.
pub const PRIVACY_ROLE_DISPATCH_TABLE_V1: [PrivacyRoleDispatchRowV1; PrivacyActionRoleV1::COUNT] = [
    row(
        PrivacyActionRoleV1::ZkAceAuthorization,
        unsupported(PrivacyRoleLimitationV1::ZkAceSoundnessDerivationIncomplete),
        PrivacyRoleEffectClassV1::ZkAceAuthorization,
    ),
    row(
        PrivacyActionRoleV1::AnonymousPgcPayment,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::AnonymousPgcPayment,
    ),
    row(
        PrivacyActionRoleV1::VeRangeRange,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::VerifyOnly,
    ),
    row(
        PrivacyActionRoleV1::ZkAmsBatchAdmission,
        unsupported(PrivacyRoleLimitationV1::ZkAmsCompositeVerifierIncomplete),
        PrivacyRoleEffectClassV1::ZkAmsBatchAdmission,
    ),
    row(
        PrivacyActionRoleV1::ZkAmsProvisionAccount,
        unsupported(PrivacyRoleLimitationV1::ZkAmsCompositeVerifierIncomplete),
        PrivacyRoleEffectClassV1::ZkAmsProvisionAccount,
    ),
    row(
        PrivacyActionRoleV1::VegaCredentialPresentation,
        unsupported(PrivacyRoleLimitationV1::VegaFigure9RelationIncomplete),
        PrivacyRoleEffectClassV1::VerifyOnly,
    ),
    row(
        PrivacyActionRoleV1::ZkX509CertificatePresentation,
        unsupported(PrivacyRoleLimitationV1::ZkX509JointRelationIncomplete),
        PrivacyRoleEffectClassV1::ZkX509Certificate,
    ),
    row(
        PrivacyActionRoleV1::JindoBatchedEvaluation,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::VerifyOnly,
    ),
    row(
        PrivacyActionRoleV1::BootleLanternPresentation,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::VerifyOnly,
    ),
    row(
        PrivacyActionRoleV1::OrchardActions,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::OrchardActions,
    ),
    row(
        PrivacyActionRoleV1::FcmpTransfer,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::ProofManagedPool,
    ),
    row(
        PrivacyActionRoleV1::IvmPrivateNoteTransition,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::ProofManagedPool,
    ),
    row(
        PrivacyActionRoleV1::PqMaspTransition,
        IMPLEMENTED,
        PrivacyRoleEffectClassV1::ProofManagedPool,
    ),
];

// Row `i` describes role `i`: the table is indexed by the role discriminant.
const _: () = {
    let mut index = 0;
    while index < PrivacyActionRoleV1::COUNT {
        assert!(PRIVACY_ROLE_DISPATCH_TABLE_V1[index].role as usize == index);
        assert!(PrivacyActionRoleV1::ALL[index] as usize == index);
        index += 1;
    }
};

/// The registry row of one role.
#[must_use]
pub const fn privacy_role_dispatch_row_v1(role: PrivacyActionRoleV1) -> PrivacyRoleDispatchRowV1 {
    PRIVACY_ROLE_DISPATCH_TABLE_V1[role as usize]
}

/// Typed refusal of a role this source tree cannot verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("privacy operation {role} of protocol {protocol_id:?} is unsupported: {limitation}")]
pub struct PrivacyUnsupportedOperationV1 {
    /// The refused role.
    pub role: PrivacyActionRoleV1,
    /// The registered protocol of the refused role.
    pub protocol_id: PrivacyProtocolIdV1,
    /// The concrete limitation behind the refusal.
    pub limitation: PrivacyRoleLimitationV1,
}

impl PrivacyUnsupportedOperationV1 {
    /// Build the refusal of `role` for `limitation`.
    #[must_use]
    pub const fn new(role: PrivacyActionRoleV1, limitation: PrivacyRoleLimitationV1) -> Self {
        Self {
            role,
            protocol_id: role.protocol_id(),
            limitation,
        }
    }
}

/// Return the registry row of a role the single dispatch verifies.
///
/// # Errors
///
/// Returns [`PrivacyUnsupportedOperationV1`] with the registered
/// limitation for a role whose verification is not implemented. Nothing about
/// the proof is examined.
pub const fn require_supported_privacy_action_role_v1(
    role: PrivacyActionRoleV1,
) -> Result<PrivacyRoleDispatchRowV1, PrivacyUnsupportedOperationV1> {
    let row = privacy_role_dispatch_row_v1(role);
    match row.verification {
        PrivacyRoleVerificationV1::Implemented => Ok(row),
        PrivacyRoleVerificationV1::Unsupported(limitation) => {
            Err(PrivacyUnsupportedOperationV1::new(role, limitation))
        }
    }
}

impl VerifiedPrivacyLedgerEffectsV1 {
    /// The effect class of this verified ledger mutation.
    #[must_use]
    pub const fn effect_class(&self) -> PrivacyRoleEffectClassV1 {
        match self {
            Self::None => PrivacyRoleEffectClassV1::VerifyOnly,
            Self::AnonymousPgcPayment(_) => PrivacyRoleEffectClassV1::AnonymousPgcPayment,
            Self::OrchardActions(_) => PrivacyRoleEffectClassV1::OrchardActions,
            Self::ProofManagedPool(_) => PrivacyRoleEffectClassV1::ProofManagedPool,
            Self::ZkAmsBatchAdmission(_) => PrivacyRoleEffectClassV1::ZkAmsBatchAdmission,
            Self::ZkAmsProvisionAccount(_) => PrivacyRoleEffectClassV1::ZkAmsProvisionAccount,
            Self::ZkAceAuthorization(_) => PrivacyRoleEffectClassV1::ZkAceAuthorization,
            Self::ZkX509Certificate(_) => PrivacyRoleEffectClassV1::ZkX509Certificate,
        }
    }

    /// Whether this effect is exactly what `role` may hand to the state executor.
    ///
    /// The effect class must be the registered class of the role, and a
    /// proof-managed pool transition must be the transition of that role: the
    /// class is shared by FCMP++, private-IVM and PQ-MASP, the transition is not.
    #[must_use]
    pub const fn discharges_role_v1(&self, role: PrivacyActionRoleV1) -> bool {
        if self.effect_class() as usize != privacy_role_dispatch_row_v1(role).effect_class as usize
        {
            return false;
        }
        match self {
            Self::ProofManagedPool(effect) => matches!(
                (effect.transition(), role),
                (
                    VerifiedProofManagedPoolTransitionV1::Fcmp { .. },
                    PrivacyActionRoleV1::FcmpTransfer
                ) | (
                    VerifiedProofManagedPoolTransitionV1::IvmPrivateNote { .. },
                    PrivacyActionRoleV1::IvmPrivateNoteTransition
                ) | (
                    VerifiedProofManagedPoolTransitionV1::PqMasp { .. },
                    PrivacyActionRoleV1::PqMaspTransition
                )
            ),
            Self::None
            | Self::AnonymousPgcPayment(_)
            | Self::OrchardActions(_)
            | Self::ZkAmsBatchAdmission(_)
            | Self::ZkAmsProvisionAccount(_)
            | Self::ZkAceAuthorization(_)
            | Self::ZkX509Certificate(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::privacy_profiles::compiled_privacy_profile_v1;

    #[test]
    fn registry_has_one_row_per_role_in_canonical_order() {
        assert_eq!(
            PRIVACY_ROLE_DISPATCH_TABLE_V1.map(|row| row.role),
            PrivacyActionRoleV1::ALL
        );
        for role in PrivacyActionRoleV1::ALL {
            let row = privacy_role_dispatch_row_v1(role);
            assert_eq!(row.role, role);
            assert_eq!(row.protocol_id(), role.protocol_id());
        }
    }

    #[test]
    fn registry_keeps_verification_effects_and_delivery_distinct() {
        use PrivacyActionRoleV1 as Role;
        use PrivacyRoleEffectClassV1 as Class;
        use PrivacyRoleLimitationV1 as Limitation;
        use PrivacyRoleStateEffectsV1 as Effects;
        let expected = [
            (
                Role::ZkAceAuthorization,
                Some(Limitation::ZkAceSoundnessDerivationIncomplete),
                Class::ZkAceAuthorization,
                Effects::Unreachable,
            ),
            (
                Role::AnonymousPgcPayment,
                None,
                Class::AnonymousPgcPayment,
                Effects::Applied,
            ),
            (
                Role::VeRangeRange,
                None,
                Class::VerifyOnly,
                Effects::VerifyOnly,
            ),
            (
                Role::ZkAmsBatchAdmission,
                Some(Limitation::ZkAmsCompositeVerifierIncomplete),
                Class::ZkAmsBatchAdmission,
                Effects::Unreachable,
            ),
            (
                Role::ZkAmsProvisionAccount,
                Some(Limitation::ZkAmsCompositeVerifierIncomplete),
                Class::ZkAmsProvisionAccount,
                Effects::Unreachable,
            ),
            (
                Role::VegaCredentialPresentation,
                Some(Limitation::VegaFigure9RelationIncomplete),
                Class::VerifyOnly,
                Effects::Unreachable,
            ),
            (
                Role::ZkX509CertificatePresentation,
                Some(Limitation::ZkX509JointRelationIncomplete),
                Class::ZkX509Certificate,
                Effects::Unreachable,
            ),
            (
                Role::JindoBatchedEvaluation,
                None,
                Class::VerifyOnly,
                Effects::VerifyOnly,
            ),
            (
                Role::BootleLanternPresentation,
                None,
                Class::VerifyOnly,
                Effects::VerifyOnly,
            ),
            (
                Role::OrchardActions,
                None,
                Class::OrchardActions,
                Effects::Applied,
            ),
            (
                Role::FcmpTransfer,
                None,
                Class::ProofManagedPool,
                Effects::Applied,
            ),
            (
                Role::IvmPrivateNoteTransition,
                None,
                Class::ProofManagedPool,
                Effects::Applied,
            ),
            (
                Role::PqMaspTransition,
                None,
                Class::ProofManagedPool,
                Effects::Applied,
            ),
        ];
        assert_eq!(expected.len(), PrivacyActionRoleV1::COUNT);
        for (role, limitation, class, effects) in expected {
            let row = privacy_role_dispatch_row_v1(role);
            let verification = limitation.map_or(
                PrivacyRoleVerificationV1::Implemented,
                PrivacyRoleVerificationV1::Unsupported,
            );
            assert_eq!(row.verification, verification, "{role}");
            assert_eq!(row.effect_class, class, "{role}");
            assert_eq!(row.state_effects(), effects, "{role}");
            // Presence, verification and effects never imply delivery.
            assert_eq!(row.delivery, PrivacyRoleDeliveryV1::NotDelivered, "{role}");
        }
    }

    #[test]
    fn no_role_is_recorded_as_delivered() {
        assert!(
            PRIVACY_ROLE_DISPATCH_TABLE_V1
                .iter()
                .all(|row| row.delivery == PrivacyRoleDeliveryV1::NotDelivered)
        );
        assert_ne!(
            PrivacyRoleDeliveryV1::NotDelivered,
            PrivacyRoleDeliveryV1::Delivered
        );
    }

    #[test]
    fn unsupported_roles_return_their_typed_limitation() {
        let mut refused = BTreeMap::new();
        for role in PrivacyActionRoleV1::ALL {
            match require_supported_privacy_action_role_v1(role) {
                Ok(row) => {
                    assert_eq!(row, privacy_role_dispatch_row_v1(role));
                    assert_eq!(row.verification, PrivacyRoleVerificationV1::Implemented);
                }
                Err(error) => {
                    assert_eq!(error.role, role);
                    assert_eq!(error.protocol_id, role.protocol_id());
                    assert_eq!(
                        privacy_role_dispatch_row_v1(role).verification,
                        PrivacyRoleVerificationV1::Unsupported(error.limitation)
                    );
                    assert!(error.to_string().contains(role.canonical_label()));
                    assert!(error.to_string().contains(error.limitation.description()));
                    refused.insert(role, error.limitation);
                }
            }
        }
        assert_eq!(
            refused.keys().copied().collect::<Vec<_>>(),
            [
                PrivacyActionRoleV1::ZkAceAuthorization,
                PrivacyActionRoleV1::ZkAmsBatchAdmission,
                PrivacyActionRoleV1::ZkAmsProvisionAccount,
                PrivacyActionRoleV1::VegaCredentialPresentation,
                PrivacyActionRoleV1::ZkX509CertificatePresentation,
            ]
        );
        assert!(
            refused
                .values()
                .all(|limitation| *limitation != PrivacyRoleLimitationV1::NativeEngineNotCompiled),
            "a default build compiles every native engine"
        );
    }

    #[test]
    fn limitation_descriptions_are_distinct_and_name_no_approval() {
        let limitations = [
            PrivacyRoleLimitationV1::ZkAceSoundnessDerivationIncomplete,
            PrivacyRoleLimitationV1::ZkAmsCompositeVerifierIncomplete,
            PrivacyRoleLimitationV1::VegaFigure9RelationIncomplete,
            PrivacyRoleLimitationV1::ZkX509JointRelationIncomplete,
            PrivacyRoleLimitationV1::NativeEngineNotCompiled,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for limitation in limitations {
            let description = limitation.description();
            assert_eq!(limitation.to_string(), description);
            assert!(seen.insert(description));
            for word in ["activat", "qualif", "approv", "govern", "audit", "review"] {
                assert!(
                    !description.contains(word),
                    "{description:?} must state a technical limitation"
                );
            }
        }
    }

    /// The registry is authoritative for dispatch support. This pins that the
    /// compiled-profile catalog refuses exactly the protocols whose roles the
    /// registry refuses in this source tree, so the two cannot drift unnoticed.
    #[test]
    fn registry_support_matches_the_current_compiled_profile_refusals() {
        for protocol in PrivacyProtocolIdV1::ALL {
            let supported = protocol
                .action_roles_v1()
                .iter()
                .map(|role| privacy_role_dispatch_row_v1(*role).verification)
                .collect::<Vec<_>>();
            let all_implemented = supported
                .iter()
                .all(|verification| *verification == PrivacyRoleVerificationV1::Implemented);
            let none_implemented = supported
                .iter()
                .all(|verification| *verification != PrivacyRoleVerificationV1::Implemented);
            assert!(
                all_implemented || none_implemented,
                "{protocol:?}: the roles of one protocol are verified together"
            );
            assert_eq!(
                compiled_privacy_profile_v1(protocol).is_ok(),
                all_implemented,
                "{protocol:?}: compiled profile and dispatch registry disagree"
            );
        }
    }

    /// The tracked operation inventory is a checked view of this registry: the
    /// typed table is authoritative and `specs/zk_operation_inventory.json`
    /// (`exact12.roles.list`) must repeat it row by row.
    #[test]
    fn operation_inventory_roles_match_the_typed_dispatch_registry() {
        let inventory: norito::json::Value =
            norito::json::from_str(include_str!("../../../specs/zk_operation_inventory.json"))
                .expect("the operation inventory is JSON");
        let rows = inventory["exact12"]["roles"]["list"]
            .as_array()
            .expect("exact12.roles.list is an array");
        assert_eq!(rows.len(), PrivacyActionRoleV1::COUNT);
        assert_eq!(
            inventory["exact12"]["roles"]["count"].as_u64(),
            Some(PrivacyActionRoleV1::COUNT as u64)
        );
        for (row, typed) in rows.iter().zip(PRIVACY_ROLE_DISPATCH_TABLE_V1) {
            let text = |key: &str| {
                row[key]
                    .as_str()
                    .unwrap_or_else(|| panic!("{}: `{key}` is a string", typed.role))
            };
            assert_eq!(text("role"), format!("{:?}", typed.role));
            assert_eq!(text("protocol"), format!("{:?}", typed.protocol_id()));
            match typed.verification {
                PrivacyRoleVerificationV1::Implemented => {
                    assert_eq!(text("verification"), "implemented", "{}", typed.role);
                    assert!(row["limitation"].as_str().is_none(), "{}", typed.role);
                }
                PrivacyRoleVerificationV1::Unsupported(limitation) => {
                    assert_eq!(text("verification"), "refused", "{}", typed.role);
                    assert_eq!(text("limitation"), format!("{limitation:?}"));
                }
            }
            assert_eq!(text("effect_class"), format!("{:?}", typed.effect_class));
            let state_effects = text("state_effects");
            match typed.state_effects() {
                PrivacyRoleStateEffectsV1::VerifyOnly => assert_eq!(state_effects, "none"),
                PrivacyRoleStateEffectsV1::Unreachable => {
                    assert_eq!(state_effects, "unreachable");
                }
                // `gated` while the handler still requires the admission gate.
                PrivacyRoleStateEffectsV1::Applied => assert!(
                    matches!(state_effects, "gated" | "implemented"),
                    "{}: {state_effects}",
                    typed.role
                ),
            }
            let delivery = match typed.delivery {
                PrivacyRoleDeliveryV1::NotDelivered => "not_delivered",
                PrivacyRoleDeliveryV1::Delivered => "delivered",
            };
            assert_eq!(text("delivery"), delivery, "{}", typed.role);
        }
    }

    #[test]
    fn verify_only_effect_discharges_exactly_the_verify_only_roles() {
        let effect = VerifiedPrivacyLedgerEffectsV1::None;
        assert_eq!(effect.effect_class(), PrivacyRoleEffectClassV1::VerifyOnly);
        for role in PrivacyActionRoleV1::ALL {
            assert_eq!(
                effect.discharges_role_v1(role),
                privacy_role_dispatch_row_v1(role).effect_class
                    == PrivacyRoleEffectClassV1::VerifyOnly,
                "{role}"
            );
        }
    }
}
