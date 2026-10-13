//! Canonical first-release privacy governance and proof-admission handlers.
//!
//! Governance checks and all deterministic validation precede storage writes.
//! Proof admission is added only through the exhaustive native verifier
//! boundary; there is deliberately no generic or opaque fallback verifier.
//!
//! `SubmitPrivacyProofV1` is the one instruction of every Exact12 role and its
//! handler is the one state executor. The handler resolves the single role of
//! the envelope once, loads trusted state for that role, calls the single
//! verifier dispatch and applies exactly the effect sealed for that role.
use super::Execute;
#[cfg(test)]
use crate::privacy_verifier::VerifiedProofManagedPoolLedgerEffectTestPartsV1;
use crate::{
    privacy::{validate_privacy_lifecycle_transition_v1, validate_privacy_registration_v1},
    privacy_engines::{
        anonymous_pgc::{
            AnonymousPgcParametersV1, TwistedElGamalCiphertextV1, TwistedElGamalPublicKeyV1,
            bootstrap::{
                AnonymousPgcBootstrapStatementV1, MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1,
                verify_bootstrap_encoded,
            },
        },
        p256::{CompressedPointV1, TranscriptBindingV1},
        proof_managed_pool_initial_root_v1,
        zk_ams::zk_ams_registry_transition_root_v1,
    },
    privacy_profiles::validate_compiled_privacy_activation_v1,
    privacy_state::{
        PrivacyActivationKeyV1, PrivacyCommitmentKeyV1, PrivacyNullifierKeyV1,
        PrivacyOrchardPoolStateV1, PrivacyPgcAccountKeyV1, PrivacyPgcAccountProvenanceV1,
        PrivacyPgcAccountStateV1, PrivacyPgcPoolInvariantKeyV1, PrivacyPgcPoolInvariantV1,
        PrivacyProofManagedAccumulatorStateV1, PrivacyProofManagedPoolAccumulatorStateV1,
        PrivacyProofManagedPoolSnapshotV1, PrivacyPublicReserveOwnerV1, PrivacyRootHeadKeyV1,
        PrivacyRootHeadRecordV1, PrivacyRootKeyV1, PrivacyRootProvenanceV1,
        PrivacyRootRetentionAnchorV1, PrivacyStateItemRecordV1, PrivacyVegaIssuerRegistryFactsV1,
        compute_privacy_pgc_account_state_root_v1, load_privacy_bootle_lantern_issuer_policy_v1,
        load_privacy_orchard_pool_snapshot_v1, load_privacy_pgc_pool_snapshot_v1,
        load_privacy_proof_managed_pool_snapshot_v1, load_privacy_vega_issuer_v1,
        load_privacy_zk_ace_policy_v1, load_privacy_zk_ams_registry_snapshot_v1,
        load_privacy_zk_x509_authoritative_state_v1, load_privacy_zk_x509_certificate_policy_v1,
        load_privacy_zk_x509_trust_anchor_v1, plan_privacy_root_history_update_v1,
        privacy_bootle_lantern_issuer_policy_count_v1, privacy_public_reserve_owner_v1,
        privacy_vega_issuer_record_count_v1, privacy_vega_issuer_registry_facts_v1,
        privacy_zk_ace_policy_count_v1, privacy_zk_x509_ca_namespace_v1,
        privacy_zk_x509_crl_lineage_count_v1, privacy_zk_x509_governance_record_counts_v1,
        proof_managed_pool_root_role_v1, resolve_qualified_privacy_activation_v1,
        validate_privacy_exact12_qualification_registration_v1,
        validate_privacy_zk_x509_policy_revocation_dependencies_v1,
        validate_privacy_zk_x509_trust_anchor_revocation_dependencies_v1,
        validate_privacy_zk_x509_trust_anchor_root_state_v1,
        validate_unanchored_privacy_root_retention_v1,
    },
    privacy_verifier::{
        PrivacyAnonymousPgcStateFailureCodeV1, PrivacyBootleLanternStateFailureCodeV1,
        PrivacyFcmpStateFailureCodeV1, PrivacyIvmPrivateNoteStateFailureCodeV1,
        PrivacyOrchardStateFailureCodeV1, PrivacyPgcVerificationStateV1,
        PrivacyPqMaspStateFailureCodeV1, PrivacyVegaStateFailureCodeV1,
        PrivacyVerificationContextFailureCodeV1, PrivacyVerificationContextV1,
        PrivacyVerificationErrorV1, PrivacyZkX509StateFailureCodeV1,
        PrivacyZkX509VerificationStateV1, VerifiedPrivacyLedgerEffectsV1,
        VerifiedProofManagedPoolLedgerEffectV1, VerifiedProofManagedPoolTransitionV1,
        verify_privacy_envelope_v1,
    },
    state::{StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    asset::AssetId,
    isi::{
        error::{InstructionExecutionError as Error, InvalidParameterError},
        privacy::{
            BootstrapPrivacyOrchardPoolV1, BootstrapPrivacyPgcAccountsV1,
            BootstrapPrivacyProofManagedPoolV1, BootstrapPrivacyZkAmsRegistryV1,
            PublishPrivacyRootV1, RegisterPrivacyBootleLanternIssuerPolicyV1,
            RegisterPrivacyExact12QualificationV1, RegisterPrivacyProtocolActivationV1,
            RegisterPrivacyVegaIssuerV1, RegisterPrivacyZkAcePolicyV1,
            RegisterPrivacyZkX509CertificatePolicyV1, RegisterPrivacyZkX509CrlV1,
            RegisterPrivacyZkX509TrustAnchorV1, RevokePrivacyBootleLanternIssuerPolicyV1,
            RevokePrivacyVegaIssuerV1, RevokePrivacyZkAcePolicyV1,
            RevokePrivacyZkX509CertificatePolicyV1, RevokePrivacyZkX509CrlV1,
            RevokePrivacyZkX509TrustAnchorV1, RotatePrivacyBootleLanternIssuerPolicyV1,
            RotatePrivacyVegaIssuerV1, RotatePrivacyZkAcePolicyV1,
            RotatePrivacyZkX509CertificatePolicyV1, RotatePrivacyZkX509CrlV1,
            RotatePrivacyZkX509TrustAnchorV1, SchedulePrivacyConsensusPolicyTighteningV1,
            SchedulePrivacyProtocolLimitsTighteningV1, SubmitPrivacyProofV1,
            TransitionPrivacyProtocolLifecycleV1,
        },
    },
    permission::Permission,
    prelude::{Account, AccountId, Quantity, Register},
    privacy::{
        BOOTLE_LANTERN_MAX_ISSUER_POLICIES_V1, BootleLanternIssuerPolicyLifecycleV1,
        BootleLanternIssuerPolicyV1, IrohaBootleLanternAnoncredStatementV1,
        IrohaIvmPrivateNoteStarkStatementV1, PRIVACY_ZK_ACE_MAX_POLICIES_V1,
        PqMaspStarkStatementV1, PrivacyActionRoleV1, PrivacyCommitmentV1,
        PrivacyConsensusPolicyTighteningV1, PrivacyFcmpInputPublicV1, PrivacyFcmpOutputTupleV1,
        PrivacyFcmpTreeRootV1, PrivacyNamespaceV1, PrivacyNullifierV1, PrivacyProofEnvelopeV1,
        PrivacyProtocolActivationRecordV1, PrivacyProtocolIdV1, PrivacyProtocolLifecycleV1,
        PrivacyProtocolLimitsTighteningV1, PrivacyRootManagementV1, PrivacyRootPublicationV1,
        PrivacyRootRoleV1, PrivacyStatementDigestV1, PrivacyStatementV1,
        PrivacyValueBalanceDirectionV1, PrivacyVegaIssuerRecordV1, PrivacyZkAcePolicyLifecycleV1,
        PrivacyZkAmsActionV1, PrivacyZkX509CrlRecordV1, PrivacyZkX509RecordLifecycleV1,
        PrivacyZkX509TrustAnchorRecordV1, TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1,
        VEGA_MAX_ISSUER_RECORD_REVISIONS_PER_LINEAGE_V1, VEGA_MAX_ISSUER_RECORDS_V1,
        ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1, ZK_X509_MAX_CRL_AGE_SECONDS_V1,
        ZK_X509_MAX_CRL_LINEAGES_V1, ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1,
        ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1, validate_vega_issuer_revocation_v1,
        validate_vega_issuer_rotation_v1, validate_zk_ace_policy_revocation_v1,
        validate_zk_ace_policy_rotation_v1, validate_zk_x509_certificate_policy_revocation_v1,
        validate_zk_x509_certificate_policy_rotation_v1, validate_zk_x509_crl_revocation_v1,
        validate_zk_x509_crl_rotation_v1, validate_zk_x509_trust_anchor_revocation_v1,
        validate_zk_x509_trust_anchor_rotation_v1, zk_ams_issuer_policy_record_digest_v1,
        zk_ams_registry_record_digest_v1,
    },
};
use iroha_executor_data_model::permission::governance::CanEnactGovernance;
use mv::storage::StorageReadOnly;
use std::collections::BTreeSet;
include!("privacy/governance_authorization.rs");
fn prepare_privacy_public_reserve_custody_v1(
    state_transaction: &StateTransaction<'_, '_>,
    reserve_asset_id: AssetId,
    owner: PrivacyPublicReserveOwnerV1,
) -> Result<(PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1), Error> {
    if privacy_public_reserve_owner_v1(
        &state_transaction.world.privacy_commitments,
        &reserve_asset_id,
    )
    .map_err(|message| Error::InvariantViolation(message.into()))?
    .is_some()
    {
        return Err(invalid_privacy_parameter(format!(
            "public-reserve asset {reserve_asset_id} already backs a governed privacy pool"
        )));
    }
    let key =
        PrivacyCommitmentKeyV1::public_reserve_custody(owner.protocol_id(), &reserve_asset_id)
            .map_err(|message| Error::InvariantViolation(message.into()))?;
    let record = PrivacyStateItemRecordV1::public_reserve_custody(reserve_asset_id, owner)
        .map_err(invalid_privacy_parameter)?;
    Ok((key, record))
}
/// Internal fault: the resolved action role and the typed statement disagree.
///
/// The role is derived from the statement, so this cannot follow from any
/// submitted bytes.
fn role_statement_invariant_v1(role: PrivacyActionRoleV1) -> Error {
    Error::InvariantViolation(
        format!("resolved action role {role} disagrees with its typed statement").into(),
    )
}
fn privacy_verification_error(error: PrivacyVerificationErrorV1) -> Error {
    let message = format!("privacy proof admission rejected: {error}");
    let invariant = match &error {
        PrivacyVerificationErrorV1::CompiledActivation(_)
        | PrivacyVerificationErrorV1::CanonicalEncoding(_) => true,
        PrivacyVerificationErrorV1::Context(detail) => {
            detail.code == PrivacyVerificationContextFailureCodeV1::ZeroGenesisHash
        }
        PrivacyVerificationErrorV1::AnonymousPgcState(detail) => !matches!(
            detail.code,
            PrivacyAnonymousPgcStateFailureCodeV1::StaleHead
                | PrivacyAnonymousPgcStateFailureCodeV1::AccountTableMismatch
                | PrivacyAnonymousPgcStateFailureCodeV1::NextRootMismatch
        ),
        PrivacyVerificationErrorV1::OrchardState(detail) => matches!(
            detail.code,
            PrivacyOrchardStateFailureCodeV1::MissingTrustedState
                | PrivacyOrchardStateFailureCodeV1::SuccessorDerivation
        ),
        PrivacyVerificationErrorV1::BootleLanternState(detail) => matches!(
            detail.code,
            PrivacyBootleLanternStateFailureCodeV1::MissingTrustedPolicy
                | PrivacyBootleLanternStateFailureCodeV1::InvalidTrustedPolicy
        ),
        PrivacyVerificationErrorV1::VegaState(detail) => {
            detail.code == PrivacyVegaStateFailureCodeV1::InvalidTrustedIssuer
        }
        PrivacyVerificationErrorV1::FcmpState(detail) => matches!(
            detail.code,
            PrivacyFcmpStateFailureCodeV1::MissingTrustedState
                | PrivacyFcmpStateFailureCodeV1::MissingCurveFrontier
                | PrivacyFcmpStateFailureCodeV1::FrontierMismatch
                | PrivacyFcmpStateFailureCodeV1::CurrentRootNotRetained
                | PrivacyFcmpStateFailureCodeV1::CurrentTypedRootMismatch
                | PrivacyFcmpStateFailureCodeV1::SuccessorDerivation
        ),
        PrivacyVerificationErrorV1::IvmPrivateNoteState(detail) => matches!(
            detail.code,
            PrivacyIvmPrivateNoteStateFailureCodeV1::MissingTrustedState
                | PrivacyIvmPrivateNoteStateFailureCodeV1::MissingNoteFrontier
                | PrivacyIvmPrivateNoteStateFailureCodeV1::FrontierMismatch
                | PrivacyIvmPrivateNoteStateFailureCodeV1::CurrentRootNotRetained
                | PrivacyIvmPrivateNoteStateFailureCodeV1::SuccessorDerivation
        ),
        PrivacyVerificationErrorV1::PqMaspState(detail) => matches!(
            detail.code,
            PrivacyPqMaspStateFailureCodeV1::MissingTrustedState
                | PrivacyPqMaspStateFailureCodeV1::MissingNoteFrontier
                | PrivacyPqMaspStateFailureCodeV1::FrontierMismatch
                | PrivacyPqMaspStateFailureCodeV1::CurrentRootNotRetained
                | PrivacyPqMaspStateFailureCodeV1::SuccessorDerivation
        ),
        PrivacyVerificationErrorV1::ZkX509State(detail) => {
            detail.code == PrivacyZkX509StateFailureCodeV1::MissingTrustedState
        }
        // A native verifier that returns the effect of another role is an internal fault.
        PrivacyVerificationErrorV1::EffectRoleMismatch(_) => true,
        PrivacyVerificationErrorV1::UnsupportedOperation(_)
        | PrivacyVerificationErrorV1::Envelope(_)
        | PrivacyVerificationErrorV1::NativeVeRange(_)
        | PrivacyVerificationErrorV1::NativeVega(_)
        | PrivacyVerificationErrorV1::NativeJindo(_)
        | PrivacyVerificationErrorV1::NativeZkAms(_)
        | PrivacyVerificationErrorV1::NativeZkX509(_)
        | PrivacyVerificationErrorV1::NativeOrchard(_)
        | PrivacyVerificationErrorV1::NativeAnonymousPgc(_)
        | PrivacyVerificationErrorV1::NativeBootleLantern(_)
        | PrivacyVerificationErrorV1::NativeFcmp(_)
        | PrivacyVerificationErrorV1::NativeIvmPrivateNote(_)
        | PrivacyVerificationErrorV1::NativePqMasp(_) => false,
        #[cfg(feature = "zk-stark")]
        PrivacyVerificationErrorV1::NativeZkAce(_) => false,
    };
    if invariant {
        Error::InvariantViolation(message.into())
    } else {
        invalid_privacy_parameter(message)
    }
}
type PreparedProofManagedNoteApplyV1 = (
    Vec<PrivacyNullifierKeyV1>,
    Vec<(PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1)>,
    PrivacyProofManagedPoolAccumulatorStateV1,
);
struct ProofManagedNoteApplyContextV1<'a, 'block, 'state> {
    effect: &'a VerifiedProofManagedPoolLedgerEffectV1,
    snapshot: &'a PrivacyProofManagedPoolSnapshotV1,
    statement_digest: PrivacyStatementDigestV1,
    block_height: u64,
    expected_action_index: u32,
    state_transaction: &'a StateTransaction<'block, 'state>,
}
enum TypedProofManagedNoteApplyV1<'a> {
    IvmPrivateNote {
        statement: &'a IrohaIvmPrivateNoteStarkStatementV1,
        nullifiers: &'a [PrivacyNullifierV1],
        output_commitments: &'a [PrivacyCommitmentV1],
        successor_state: &'a PrivacyProofManagedAccumulatorStateV1,
    },
    PqMasp {
        statement: &'a PqMaspStarkStatementV1,
        nullifiers: &'a [PrivacyNullifierV1],
        output_commitments: &'a [PrivacyCommitmentV1],
        successor_state: &'a PrivacyProofManagedAccumulatorStateV1,
    },
}
fn prepare_proof_managed_note_apply_v1(
    context: ProofManagedNoteApplyContextV1<'_, '_, '_>,
    transition: TypedProofManagedNoteApplyV1<'_>,
) -> Result<PreparedProofManagedNoteApplyV1, Error> {
    let ProofManagedNoteApplyContextV1 {
        effect,
        snapshot,
        statement_digest,
        block_height,
        expected_action_index,
        state_transaction,
    } = context;
    let (
        protocol_label,
        statement_nullifiers,
        statement_outputs,
        verified_nullifiers,
        verified_outputs,
        successor_state,
    ) = match transition {
        TypedProofManagedNoteApplyV1::IvmPrivateNote {
            statement,
            nullifiers,
            output_commitments,
            successor_state,
        } => (
            "private-IVM",
            statement.nullifiers.as_slice(),
            statement.output_commitments.as_slice(),
            nullifiers,
            output_commitments,
            successor_state,
        ),
        TypedProofManagedNoteApplyV1::PqMasp {
            statement,
            nullifiers,
            output_commitments,
            successor_state,
        } => (
            "PQ-MASP",
            statement.nullifiers.as_slice(),
            statement.output_commitments.as_slice(),
            nullifiers,
            output_commitments,
            successor_state,
        ),
    };
    let expected_successor =
        snapshot
            .derive_note_successor(statement_outputs)
            .map_err(|error| {
                Error::InvariantViolation(
                format!(
                    "trusted {protocol_label} note frontier could not derive its successor: {error}"
                )
                .into(),
            )
            })?;
    if verified_nullifiers != statement_nullifiers
        || verified_outputs != statement_outputs
        || successor_state != &expected_successor
        || effect.next_epoch() != expected_successor.epoch()
        || effect.next_root() != expected_successor.root()
    {
        return Err(Error::InvariantViolation(
            format!(
                "native {protocol_label} effect differs from its statement or validator-derived successor"
            )
            .into(),
        ));
    }
    let nullifier_count = u32::try_from(verified_nullifiers.len()).map_err(|_| {
        Error::InvariantViolation(
            format!("verified {protocol_label} nullifier count overflow").into(),
        )
    })?;
    let output_count = u32::try_from(verified_outputs.len()).map_err(|_| {
        Error::InvariantViolation(format!("verified {protocol_label} output count overflow").into())
    })?;
    let mut seen_nullifier_keys = BTreeSet::new();
    let mut nullifier_keys = Vec::new();
    nullifier_keys
        .try_reserve_exact(verified_nullifiers.len())
        .map_err(|_| {
            Error::InvariantViolation(
                format!("verified {protocol_label} nullifier allocation failed").into(),
            )
        })?;
    for nullifier in verified_nullifiers {
        let key = PrivacyNullifierKeyV1::proof_managed_nullifier(effect.namespace(), *nullifier)
            .map_err(|error| {
                Error::InvariantViolation(
                    format!("verified {protocol_label} nullifier is invalid: {error}").into(),
                )
            })?;
        if !seen_nullifier_keys.insert(key)
            || state_transaction
                .world
                .privacy_nullifiers
                .get(&key)
                .is_some()
        {
            return Err(invalid_privacy_parameter(format!(
                "verified {protocol_label} nullifier is duplicate or already consumed"
            )));
        }
        nullifier_keys.push(key);
    }
    let mut seen_commitment_keys = BTreeSet::new();
    let mut output_records = Vec::new();
    output_records
        .try_reserve_exact(verified_outputs.len())
        .map_err(|_| {
            Error::InvariantViolation(
                format!("verified {protocol_label} output allocation failed").into(),
            )
        })?;
    for (output_index, commitment) in verified_outputs.iter().copied().enumerate() {
        let key =
            PrivacyCommitmentKeyV1::proof_managed_pool_commitment(effect.namespace(), commitment)
                .map_err(|error| {
                Error::InvariantViolation(
                    format!("verified {protocol_label} commitment is invalid: {error}").into(),
                )
            })?;
        if !seen_commitment_keys.insert(key)
            || state_transaction
                .world
                .privacy_commitments
                .get(&key)
                .is_some()
        {
            return Err(invalid_privacy_parameter(format!(
                "verified {protocol_label} output is duplicate or already exists"
            )));
        }
        let output_index = u32::try_from(output_index).map_err(|_| {
            Error::InvariantViolation(
                format!("verified {protocol_label} output index overflow").into(),
            )
        })?;
        let append_position = snapshot
            .output_count()
            .checked_add(u64::from(output_index))
            .ok_or_else(|| {
                Error::InvariantViolation(
                    format!("verified {protocol_label} append position overflow").into(),
                )
            })?;
        let record = PrivacyStateItemRecordV1::proof_managed_pool_verified_commitment(
            effect.bootstrap_digest(),
            statement_digest,
            effect.next_epoch(),
            output_index,
            append_position,
            nullifier_count,
            output_count,
            block_height,
            expected_action_index,
        )
        .map_err(invalid_privacy_parameter)?;
        output_records.push((key, record));
    }
    Ok((
        nullifier_keys,
        output_records,
        PrivacyProofManagedPoolAccumulatorStateV1::PrivateNote(expected_successor),
    ))
}
impl Execute for RegisterPrivacyProtocolActivationV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let current_height = state_transaction._curr_block.height().get();
        let key = PrivacyActivationKeyV1::new(self.activation.protocol_id);
        validate_privacy_registration_v1(
            &state_transaction
                .world
                .privacy_consensus_policy
                .get()
                .current_limits,
            state_transaction.world.privacy_activations.get(&key),
            &self.activation,
            current_height,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("privacy activation registration rejected: {error}"))
        })?;
        state_transaction
            .world
            .privacy_activations
            .insert(key, self.activation);
        Ok(())
    }
}
impl Execute for RegisterPrivacyExact12QualificationV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        if state_transaction
            .world
            .privacy_exact12_qualification
            .get()
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "privacy Exact12 qualification is immutable and already registered",
            ));
        }
        validate_privacy_exact12_qualification_registration_v1(
            &self.qualification,
            &state_transaction.chain_id,
            state_transaction.network_id,
            state_transaction.block_height(),
            &state_transaction.world.privacy_activations,
            state_transaction.commit_topology.get(),
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "privacy Exact12 qualification registration rejected: {error}"
            ))
        })?;
        *state_transaction
            .world
            .privacy_exact12_qualification
            .get_mut() = Some(self.qualification);
        Ok(())
    }
}
impl Execute for SchedulePrivacyConsensusPolicyTighteningV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let incoming_height = state_transaction.block_height();
        let current = *state_transaction.world.privacy_consensus_policy.get();
        current.validate().map_err(|error| {
            Error::InvariantViolation(
                format!("persisted privacy consensus policy is invalid: {error}").into(),
            )
        })?;
        if current.pending_tightening.is_some() {
            return Err(invalid_privacy_parameter(
                "privacy consensus policy already has a pending tightening",
            ));
        }
        let pending = PrivacyConsensusPolicyTighteningV1 {
            scheduled_at_height: incoming_height,
            effective_at_height: self.effective_at_height,
            next_limits: self.next_limits,
        };
        pending
            .validate_against(&current.current_limits)
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "privacy consensus policy tightening rejected: {error}"
                ))
            })?;
        validate_unanchored_privacy_root_retention_v1(
            &state_transaction.world.privacy_roots,
            self.next_limits.retained_root_count,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "privacy consensus policy tightening rejected: {error}"
            ))
        })?;
        *state_transaction.world.privacy_consensus_policy.get_mut() =
            iroha_data_model::privacy::PrivacyConsensusPolicyV1 {
                current_limits: current.current_limits,
                pending_tightening: Some(pending),
            };
        Ok(())
    }
}
impl Execute for SchedulePrivacyProtocolLimitsTighteningV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let incoming_height = state_transaction.block_height();
        let key = PrivacyActivationKeyV1::new(self.protocol_id);
        let current = state_transaction
            .world
            .privacy_activations
            .get(&key)
            .copied()
            .ok_or_else(|| {
                invalid_privacy_parameter(format!(
                    "privacy protocol {:?} is not registered",
                    self.protocol_id
                ))
            })?;
        current.validate().map_err(|error| {
            Error::InvariantViolation(
                format!("persisted privacy activation is invalid: {error}").into(),
            )
        })?;
        if current.pending_protocol_limits_tightening.is_some() {
            return Err(invalid_privacy_parameter(format!(
                "privacy protocol {:?} already has a pending limit tightening",
                self.protocol_id
            )));
        }
        let pending = PrivacyProtocolLimitsTighteningV1 {
            scheduled_at_height: incoming_height,
            effective_at_height: self.effective_at_height,
            next_limits: self.next_limits,
        };
        pending
            .validate_against(&current.protocol_limits)
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "privacy protocol-limit tightening rejected: {error}"
                ))
            })?;
        let mut executable_successor = current;
        executable_successor.protocol_limits = self.next_limits;
        executable_successor.pending_protocol_limits_tightening = None;
        validate_compiled_privacy_activation_v1(&executable_successor).map_err(|error| {
            invalid_privacy_parameter(format!(
                "privacy protocol-limit tightening is not executable: {error}"
            ))
        })?;
        let mut next = current;
        next.pending_protocol_limits_tightening = Some(pending);
        state_transaction
            .world
            .privacy_activations
            .insert(key, next);
        Ok(())
    }
}
impl Execute for TransitionPrivacyProtocolLifecycleV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let current_height = state_transaction._curr_block.height().get();
        let key = PrivacyActivationKeyV1::new(self.protocol_id);
        let current = state_transaction
            .world
            .privacy_activations
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                invalid_privacy_parameter(format!(
                    "privacy protocol {:?} is not registered",
                    self.protocol_id
                ))
            })?;
        validate_privacy_lifecycle_transition_v1(&current, self.next_lifecycle, current_height)
            .map_err(|error| {
                invalid_privacy_parameter(format!("privacy lifecycle transition rejected: {error}"))
            })?;
        let mut next = current;
        next.lifecycle = self.next_lifecycle;
        state_transaction
            .world
            .privacy_activations
            .insert(key, next);
        Ok(())
    }
}
impl Execute for PublishPrivacyRootV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        self.publication.validate().map_err(|error| {
            invalid_privacy_parameter(format!("privacy root publication rejected: {error}"))
        })?;
        if self.publication.role == PrivacyRootRoleV1::PgcAccountState {
            return Err(invalid_privacy_parameter(
                "PGC account-state roots require a complete typed account bootstrap",
            ));
        }
        if self.publication.role == PrivacyRootRoleV1::AccountRegistry {
            return Err(invalid_privacy_parameter(
                "ZK-AMS AccountRegistry roots require the typed registry bootstrap and verified proof successors",
            ));
        }
        if self.publication.namespace.protocol_id() == PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 {
            return Err(invalid_privacy_parameter(
                "X.509 CA and CRL roots are derived atomically by their typed governance instructions and cannot be published generically",
            ));
        }
        let current_height = state_transaction._curr_block.height().get();
        let activation_key = PrivacyActivationKeyV1::new(self.publication.namespace.protocol_id());
        let activation = state_transaction
            .world
            .privacy_activations
            .get(&activation_key)
            .copied()
            .ok_or_else(|| {
                invalid_privacy_parameter(format!(
                    "privacy protocol {:?} is not registered",
                    self.publication.namespace.protocol_id()
                ))
            })?;
        activation.validate().map_err(|error| {
            invalid_privacy_parameter(format!("registered privacy activation is invalid: {error}"))
        })?;
        if matches!(activation.lifecycle, PrivacyProtocolLifecycleV1::Retired(_)) {
            return Err(invalid_privacy_parameter(
                "cannot publish a root for a retired privacy protocol",
            ));
        }
        if self.publication.role.management() == PrivacyRootManagementV1::ProofManaged {
            return Err(invalid_privacy_parameter(
                "proof-managed privacy roots require their protocol-specific typed bootstrap and cannot be published generically",
            ));
        }
        let head_key = PrivacyRootHeadKeyV1::new(self.publication.namespace, self.publication.role)
            .map_err(invalid_privacy_parameter)?;
        let current_head = state_transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .copied();
        match (self.publication.role.management(), current_head) {
            (PrivacyRootManagementV1::ProofManaged, Some(_)) => {
                return Err(invalid_privacy_parameter(
                    "governance may initialize but cannot advance a proof-managed privacy root",
                ));
            }
            (PrivacyRootManagementV1::GovernanceManaged, Some(head))
                if self.publication.epoch <= head.epoch() =>
            {
                return Err(invalid_privacy_parameter(format!(
                    "governance-managed privacy root epoch must advance current epoch {}",
                    head.epoch()
                )));
            }
            _ => {}
        }
        if let Some(head) = current_head {
            let retained_head = PrivacyRootKeyV1::new(
                head_key.namespace(),
                head_key.role(),
                head.epoch(),
                head.root(),
            )
            .map_err(invalid_privacy_parameter)?;
            if state_transaction.world.privacy_roots.get(&retained_head) != Some(&head.provenance())
            {
                return Err(Error::InvariantViolation(
                    "privacy root head is inconsistent with retained history".into(),
                ));
            }
        } else if state_transaction
            .world
            .privacy_roots
            .range(PrivacyRootKeyV1::history_range(
                head_key.namespace(),
                head_key.role(),
            ))
            .next()
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "privacy root history exists without a current head".into(),
            ));
        }
        let root_key = PrivacyRootKeyV1::new(
            self.publication.namespace,
            self.publication.role,
            self.publication.epoch,
            self.publication.root,
        )
        .map_err(invalid_privacy_parameter)?;
        let publication_digest = self.publication.digest().map_err(|error| {
            invalid_privacy_parameter(format!("privacy root publication encoding failed: {error}"))
        })?;
        let provenance = PrivacyRootProvenanceV1::governance(publication_digest, current_height)
            .map_err(invalid_privacy_parameter)?;
        let removals = plan_privacy_root_history_update_v1(
            &state_transaction.world.privacy_roots,
            &[root_key],
            state_transaction
                .world
                .privacy_consensus_policy
                .get()
                .admission_retained_root_count(),
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("privacy root publication rejected: {error}"))
        })?;
        if !removals.is_empty() {
            return Err(invalid_privacy_parameter(
                "non-PGC privacy root retention rollover is unavailable without a typed anchor-chain validator",
            ));
        }
        let retention_anchor = removals
            .last()
            .map(|key| PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root()))
            .transpose()
            .map_err(invalid_privacy_parameter)?
            .or_else(|| current_head.and_then(PrivacyRootHeadRecordV1::retention_anchor));
        let next_head = PrivacyRootHeadRecordV1::new(
            self.publication.epoch,
            self.publication.root,
            provenance,
            retention_anchor,
        )
        .map_err(invalid_privacy_parameter)?;
        for key in removals {
            state_transaction.world.privacy_roots.remove(key);
        }
        state_transaction
            .world
            .privacy_roots
            .insert(root_key, provenance);
        state_transaction
            .world
            .privacy_root_heads
            .insert(head_key, next_head);
        Ok(())
    }
}
impl Execute for BootstrapPrivacyOrchardPoolV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation("Orchard pool bootstrap canonical encoding failed".into())
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        self.bootstrap.validate().map_err(|error| {
            invalid_privacy_parameter(format!("Orchard pool bootstrap rejected: {error}"))
        })?;
        let current_height = state_transaction._curr_block.height().get();
        let activation_key =
            PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::OrchardHalo2ActionsV1);
        let activation = state_transaction
            .world
            .privacy_activations
            .get(&activation_key)
            .copied()
            .ok_or_else(|| {
                invalid_privacy_parameter("Orchard privacy protocol is not registered")
            })?;
        validate_compiled_privacy_activation_v1(&activation).map_err(|error| {
            Error::InvariantViolation(
                format!("registered Orchard activation is not executable: {error}").into(),
            )
        })?;
        activation.validate().map_err(|error| {
            invalid_privacy_parameter(format!("registered Orchard activation is invalid: {error}"))
        })?;
        let PrivacyProtocolLifecycleV1::Active(active) = activation.lifecycle else {
            return Err(invalid_privacy_parameter(
                "cannot bootstrap a pool before Orchard is active",
            ));
        };
        if current_height < active.state_since_height {
            return Err(invalid_privacy_parameter(format!(
                "Orchard activation is not effective until block {}",
                active.state_since_height
            )));
        }
        super::asset::isi::validate_committed_public_balance_scope(
            state_transaction,
            &self.bootstrap.asset_definition_id,
            self.bootstrap.public_balance_scope,
            "Orchard pool bootstrap",
        )?;
        if state_transaction
            .world
            .accounts
            .get(&self.bootstrap.reserve_account)
            .is_none()
        {
            return Err(invalid_privacy_parameter(format!(
                "Orchard reserve account `{}` does not exist",
                self.bootstrap.reserve_account
            )));
        }
        let namespace = self.bootstrap.namespace();
        let state_key = PrivacyCommitmentKeyV1::orchard_pool_state(namespace)
            .map_err(invalid_privacy_parameter)?;
        let head_key =
            PrivacyRootHeadKeyV1::new(namespace, PrivacyRootRoleV1::NoteCommitmentAnchor)
                .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "Orchard pool is already initialized",
            ));
        }
        if state_transaction
            .world
            .privacy_commitments
            .get(&state_key)
            .is_some()
            || state_transaction
                .world
                .privacy_roots
                .range(PrivacyRootKeyV1::history_range(
                    namespace,
                    PrivacyRootRoleV1::NoteCommitmentAnchor,
                ))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_nullifiers
                .range(PrivacyNullifierKeyV1::orchard_nullifier_range(namespace))
                .next()
                .is_some()
        {
            return Err(Error::InvariantViolation(
                "Orchard pool state exists without a current typed head".into(),
            ));
        }
        let bootstrap_digest = self.bootstrap.digest().map_err(|error| {
            Error::InvariantViolation(
                format!("Orchard pool bootstrap canonical encoding failed: {error}").into(),
            )
        })?;
        let pool_state = PrivacyOrchardPoolStateV1::bootstrap(self.bootstrap.clone())
            .map_err(invalid_privacy_parameter)?;
        let state_record = PrivacyStateItemRecordV1::orchard_pool_state(pool_state.clone())
            .map_err(invalid_privacy_parameter)?;
        let reserve_custody = prepare_privacy_public_reserve_custody_v1(
            state_transaction,
            AssetId::with_scope(
                self.bootstrap.asset_definition_id.clone(),
                self.bootstrap.reserve_account.clone(),
                self.bootstrap.public_balance_scope,
            ),
            PrivacyPublicReserveOwnerV1::Orchard {
                namespace,
                bootstrap_digest,
            },
        )?;
        let root_provenance =
            PrivacyRootProvenanceV1::orchard_pool_bootstrap(bootstrap_digest, current_height)
                .map_err(invalid_privacy_parameter)?;
        let root_key = PrivacyRootKeyV1::new(
            namespace,
            PrivacyRootRoleV1::NoteCommitmentAnchor,
            pool_state.epoch(),
            pool_state.root(),
        )
        .map_err(invalid_privacy_parameter)?;
        let root_head = PrivacyRootHeadRecordV1::new(
            pool_state.epoch(),
            pool_state.root(),
            root_provenance,
            None,
        )
        .map_err(invalid_privacy_parameter)?;
        let removals = plan_privacy_root_history_update_v1(
            &state_transaction.world.privacy_roots,
            &[root_key],
            state_transaction
                .world
                .privacy_consensus_policy
                .get()
                .admission_retained_root_count(),
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("Orchard bootstrap root rejected: {error}"))
        })?;
        if !removals.is_empty() {
            return Err(Error::InvariantViolation(
                "new Orchard root history unexpectedly requires pruning".into(),
            ));
        }
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(state_key, state_record);
        state_transaction
            .world
            .privacy_commitments
            .insert(reserve_custody.0, reserve_custody.1);
        state_transaction
            .world
            .privacy_roots
            .insert(root_key, root_provenance);
        state_transaction
            .world
            .privacy_root_heads
            .insert(head_key, root_head);
        Ok(())
    }
}
impl Execute for BootstrapPrivacyProofManagedPoolV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        const INITIAL_EPOCH: u64 = 1;
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "proof-managed pool bootstrap canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        self.bootstrap.validate().map_err(|error| {
            invalid_privacy_parameter(format!("proof-managed pool bootstrap rejected: {error}"))
        })?;
        let protocol_id = self.bootstrap.protocol_id();
        let namespace = self.bootstrap.namespace();
        let root_role =
            proof_managed_pool_root_role_v1(namespace).map_err(invalid_privacy_parameter)?;
        if root_role != self.bootstrap.root_role() {
            return Err(Error::InvariantViolation(
                "proof-managed bootstrap derived inconsistent root roles".into(),
            ));
        }
        let current_height = state_transaction._curr_block.height().get();
        let activation_key = PrivacyActivationKeyV1::new(protocol_id);
        let activation = state_transaction
            .world
            .privacy_activations
            .get(&activation_key)
            .copied()
            .ok_or_else(|| {
                invalid_privacy_parameter(format!(
                    "proof-managed privacy protocol {protocol_id:?} is not registered"
                ))
            })?;
        validate_compiled_privacy_activation_v1(&activation).map_err(|error| {
            Error::InvariantViolation(
                format!(
                    "registered proof-managed activation {protocol_id:?} is not executable: {error}"
                )
                .into(),
            )
        })?;
        activation.validate().map_err(|error| {
            invalid_privacy_parameter(format!(
                "registered proof-managed activation {protocol_id:?} is invalid: {error}"
            ))
        })?;
        let PrivacyProtocolLifecycleV1::Active(active) = activation.lifecycle else {
            return Err(invalid_privacy_parameter(format!(
                "cannot bootstrap a pool before {protocol_id:?} is active"
            )));
        };
        if current_height < active.state_since_height {
            return Err(invalid_privacy_parameter(format!(
                "{protocol_id:?} activation is not effective until block {}",
                active.state_since_height
            )));
        }
        state_transaction
            .world
            .asset_definition(self.bootstrap.asset_definition_id())
            .map_err(Error::from)?;
        if let Some(public_balance_scope) = self.bootstrap.public_balance_scope() {
            super::asset::isi::validate_committed_public_balance_scope(
                state_transaction,
                self.bootstrap.asset_definition_id(),
                public_balance_scope,
                "private-IVM pool bootstrap",
            )?;
        }
        if let Some(reserve_account) = self.bootstrap.reserve_account()
            && state_transaction
                .world
                .accounts
                .get(reserve_account)
                .is_none()
        {
            return Err(invalid_privacy_parameter(format!(
                "proof-managed pool reserve account `{reserve_account}` does not exist"
            )));
        }
        let config_key = PrivacyCommitmentKeyV1::proof_managed_pool_config(namespace)
            .map_err(invalid_privacy_parameter)?;
        let head_key =
            PrivacyRootHeadKeyV1::new(namespace, root_role).map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(format!(
                "proof-managed pool {namespace:?} is already initialized"
            )));
        }
        if state_transaction
            .world
            .privacy_commitments
            .get(&config_key)
            .is_some()
            || state_transaction
                .world
                .privacy_commitments
                .range(PrivacyCommitmentKeyV1::proof_managed_pool_commitment_range(
                    namespace,
                ))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_commitments
                .range(PrivacyCommitmentKeyV1::fcmp_output_range(namespace))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_nullifiers
                .range(PrivacyNullifierKeyV1::proof_managed_nullifier_range(
                    namespace,
                ))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_nullifiers
                .range(PrivacyNullifierKeyV1::fcmp_key_image_range(namespace))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_roots
                .range(PrivacyRootKeyV1::history_range(namespace, root_role))
                .next()
                .is_some()
        {
            return Err(Error::InvariantViolation(
                "proof-managed pool state exists without a current typed head".into(),
            ));
        }
        let bootstrap_digest = self.bootstrap.digest().map_err(|error| {
            Error::InvariantViolation(
                format!("proof-managed pool bootstrap canonical encoding failed: {error}").into(),
            )
        })?;
        let reserve_custody = match (
            self.bootstrap.reserve_account(),
            self.bootstrap.public_balance_scope(),
        ) {
            (Some(reserve_account), Some(scope)) => {
                Some(prepare_privacy_public_reserve_custody_v1(
                    state_transaction,
                    AssetId::with_scope(
                        self.bootstrap.asset_definition_id().clone(),
                        reserve_account.clone(),
                        scope,
                    ),
                    PrivacyPublicReserveOwnerV1::PrivateIvm {
                        namespace,
                        bootstrap_digest,
                    },
                )?)
            }
            (None, None) => None,
            _ => {
                return Err(Error::InvariantViolation(
                    "proof-managed reserve account and scope must be present together".into(),
                ));
            }
        };
        let initial_root =
            proof_managed_pool_initial_root_v1(&self.bootstrap).map_err(|error| {
                Error::InvariantViolation(
                    format!("proof-managed pool native root derivation failed: {error}").into(),
                )
            })?;
        let config_record = PrivacyStateItemRecordV1::proof_managed_pool_bootstrap(
            self.bootstrap.clone(),
            bootstrap_digest,
            initial_root,
            current_height,
        )
        .map_err(invalid_privacy_parameter)?;
        let output_count = self.bootstrap.initial_fcmp_outputs().map_or_else(
            || {
                self.bootstrap
                    .initial_note_commitments()
                    .map_or(0, |values| values.len())
            },
            |values| values.len(),
        );
        let mut output_records = Vec::new();
        output_records
            .try_reserve_exact(output_count)
            .map_err(|_| {
                Error::InvariantViolation(
                    "proof-managed pool bootstrap output allocation failed".into(),
                )
            })?;
        if let Some(outputs) = self.bootstrap.initial_fcmp_outputs() {
            for (position, output) in outputs.iter().copied().enumerate() {
                let key = PrivacyCommitmentKeyV1::fcmp_output(namespace, output.output_id())
                    .map_err(invalid_privacy_parameter)?;
                if state_transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .is_some()
                {
                    return Err(Error::InvariantViolation(
                        "FCMP++ genesis output exists without pool configuration".into(),
                    ));
                }
                let position = u64::try_from(position).map_err(|_| {
                    Error::InvariantViolation("FCMP++ genesis output position overflow".into())
                })?;
                let record = PrivacyStateItemRecordV1::fcmp_bootstrap_output(
                    bootstrap_digest,
                    output,
                    position,
                    current_height,
                )
                .map_err(invalid_privacy_parameter)?;
                output_records.push((key, record));
            }
        } else if let Some(commitments) = self.bootstrap.initial_note_commitments() {
            for (position, commitment) in commitments.iter().copied().enumerate() {
                let key =
                    PrivacyCommitmentKeyV1::proof_managed_pool_commitment(namespace, commitment)
                        .map_err(invalid_privacy_parameter)?;
                if state_transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .is_some()
                {
                    return Err(Error::InvariantViolation(
                        "proof-managed genesis commitment exists without pool configuration".into(),
                    ));
                }
                let position = u64::try_from(position).map_err(|_| {
                    Error::InvariantViolation(
                        "proof-managed genesis commitment position overflow".into(),
                    )
                })?;
                let record = PrivacyStateItemRecordV1::proof_managed_pool_bootstrap_commitment(
                    bootstrap_digest,
                    position,
                    current_height,
                )
                .map_err(invalid_privacy_parameter)?;
                output_records.push((key, record));
            }
        } else {
            return Err(Error::InvariantViolation(
                "proof-managed bootstrap has no canonical output set".into(),
            ));
        }
        let root_provenance = PrivacyRootProvenanceV1::proof_managed_pool_bootstrap(
            bootstrap_digest,
            protocol_id,
            current_height,
        )
        .map_err(invalid_privacy_parameter)?;
        let root_key = PrivacyRootKeyV1::new(namespace, root_role, INITIAL_EPOCH, initial_root)
            .map_err(invalid_privacy_parameter)?;
        let root_head =
            PrivacyRootHeadRecordV1::new(INITIAL_EPOCH, initial_root, root_provenance, None)
                .map_err(invalid_privacy_parameter)?;
        let removals = plan_privacy_root_history_update_v1(
            &state_transaction.world.privacy_roots,
            &[root_key],
            state_transaction
                .world
                .privacy_consensus_policy
                .get()
                .admission_retained_root_count(),
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "proof-managed pool bootstrap root rejected: {error}"
            ))
        })?;
        if !removals.is_empty() {
            return Err(Error::InvariantViolation(
                "new proof-managed root history unexpectedly requires pruning".into(),
            ));
        }
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(config_key, config_record);
        if let Some((key, record)) = reserve_custody {
            state_transaction
                .world
                .privacy_commitments
                .insert(key, record);
        }
        for (key, record) in output_records {
            state_transaction
                .world
                .privacy_commitments
                .insert(key, record);
        }
        state_transaction
            .world
            .privacy_roots
            .insert(root_key, root_provenance);
        state_transaction
            .world
            .privacy_root_heads
            .insert(head_key, root_head);
        Ok(())
    }
}
impl Execute for BootstrapPrivacyZkAmsRegistryV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "ZK-AMS registry bootstrap canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        self.bootstrap.validate().map_err(|error| {
            invalid_privacy_parameter(format!("ZK-AMS registry bootstrap rejected: {error}"))
        })?;
        CompressedPointV1::from_slice(self.bootstrap.issuer_public_key.as_bytes()).map_err(
            |error| {
                invalid_privacy_parameter(format!(
                    "ZK-AMS registry bootstrap issuer key rejected: {error}"
                ))
            },
        )?;
        let current_height = state_transaction._curr_block.height().get();
        let namespace = self.bootstrap.namespace();
        let activation_key = PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::IrohaZkAmsV1);
        let activation = state_transaction
            .world
            .privacy_activations
            .get(&activation_key)
            .copied()
            .ok_or_else(|| {
                invalid_privacy_parameter("ZK-AMS privacy protocol is not registered")
            })?;
        validate_compiled_privacy_activation_v1(&activation).map_err(|error| {
            Error::InvariantViolation(
                format!("registered ZK-AMS activation is not executable: {error}").into(),
            )
        })?;
        activation.validate().map_err(|error| {
            invalid_privacy_parameter(format!("registered ZK-AMS activation is invalid: {error}"))
        })?;
        let PrivacyProtocolLifecycleV1::Active(active) = activation.lifecycle else {
            return Err(invalid_privacy_parameter(
                "cannot bootstrap a registry before ZK-AMS is active",
            ));
        };
        if current_height < active.state_since_height {
            return Err(invalid_privacy_parameter(format!(
                "ZK-AMS activation is not effective until block {}",
                active.state_since_height
            )));
        }
        let head_key = PrivacyRootHeadKeyV1::new(namespace, PrivacyRootRoleV1::AccountRegistry)
            .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "ZK-AMS AccountRegistry is already initialized",
            ));
        }
        if state_transaction
            .world
            .privacy_roots
            .range(PrivacyRootKeyV1::history_range(
                namespace,
                PrivacyRootRoleV1::AccountRegistry,
            ))
            .next()
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "ZK-AMS AccountRegistry history exists without a current head".into(),
            ));
        }
        if state_transaction
            .world
            .privacy_commitments
            .range(PrivacyCommitmentKeyV1::zk_ams_issuer_policy_record_range(
                namespace,
            ))
            .next()
            .is_some()
            || state_transaction
                .world
                .privacy_commitments
                .range(PrivacyCommitmentKeyV1::zk_ams_phc_range(namespace))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_commitments
                .range(PrivacyCommitmentKeyV1::zk_ams_seed_key_range(namespace))
                .next()
                .is_some()
            || state_transaction
                .world
                .privacy_nullifiers
                .range(
                    crate::privacy_state::PrivacyNullifierKeyV1::zk_ams_key_image_range(namespace),
                )
                .next()
                .is_some()
        {
            return Err(Error::InvariantViolation(
                "ZK-AMS state items exist without a current registry head".into(),
            ));
        }
        let bootstrap_digest = self.bootstrap.digest();
        let issuer_record_key = PrivacyCommitmentKeyV1::zk_ams_issuer_policy_record(
            namespace,
            self.bootstrap.issuer_policy_record_digest(),
        )
        .map_err(invalid_privacy_parameter)?;
        let issuer_record =
            PrivacyStateItemRecordV1::zk_ams_governance(bootstrap_digest, current_height)
                .map_err(invalid_privacy_parameter)?;
        let root_key = PrivacyRootKeyV1::new(
            namespace,
            PrivacyRootRoleV1::AccountRegistry,
            self.bootstrap.initial_registry_epoch,
            self.bootstrap.initial_registry_root,
        )
        .map_err(invalid_privacy_parameter)?;
        let root_provenance =
            PrivacyRootProvenanceV1::zk_ams_registry_bootstrap(bootstrap_digest, current_height)
                .map_err(invalid_privacy_parameter)?;
        let root_head = PrivacyRootHeadRecordV1::new(
            self.bootstrap.initial_registry_epoch,
            self.bootstrap.initial_registry_root,
            root_provenance,
            None,
        )
        .map_err(invalid_privacy_parameter)?;
        let removals = plan_privacy_root_history_update_v1(
            &state_transaction.world.privacy_roots,
            &[root_key],
            state_transaction
                .world
                .privacy_consensus_policy
                .get()
                .current_limits
                .retained_root_count,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("ZK-AMS registry bootstrap root rejected: {error}"))
        })?;
        if !removals.is_empty() {
            return Err(Error::InvariantViolation(
                "new ZK-AMS registry history unexpectedly requires pruning".into(),
            ));
        }
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(issuer_record_key, issuer_record);
        state_transaction
            .world
            .privacy_roots
            .insert(root_key, root_provenance);
        state_transaction
            .world
            .privacy_root_heads
            .insert(head_key, root_head);
        Ok(())
    }
}
impl Execute for BootstrapPrivacyPgcAccountsV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation("privacy PGC bootstrap canonical encoding failed".into())
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        self.bootstrap.validate().map_err(|error| {
            invalid_privacy_parameter(format!("privacy PGC account bootstrap rejected: {error}"))
        })?;
        self.proof.validate().map_err(|error| {
            invalid_privacy_parameter(format!("privacy PGC bootstrap proof rejected: {error}"))
        })?;
        let native_proof_cap = u32::try_from(MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1).map_err(|_| {
            Error::InvariantViolation(
                "native PGC bootstrap proof cap cannot be represented by consensus".into(),
            )
        })?;
        if native_proof_cap != TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1 {
            return Err(Error::InvariantViolation(
                "native and data-model PGC bootstrap proof caps differ".into(),
            ));
        }
        let current_height = state_transaction._curr_block.height().get();
        let activation_key = PrivacyActivationKeyV1::new(self.bootstrap.namespace.protocol_id());
        let activation = state_transaction
            .world
            .privacy_activations
            .get(&activation_key)
            .copied()
            .ok_or_else(|| {
                invalid_privacy_parameter("Anonymous PGC privacy protocol is not registered")
            })?;
        validate_compiled_privacy_activation_v1(&activation).map_err(|error| {
            Error::InvariantViolation(
                format!("registered Anonymous PGC activation is not executable: {error}").into(),
            )
        })?;
        activation.validate().map_err(|error| {
            invalid_privacy_parameter(format!(
                "registered Anonymous PGC activation is invalid: {error}"
            ))
        })?;
        let PrivacyProtocolLifecycleV1::Active(active) = activation.lifecycle else {
            return Err(invalid_privacy_parameter(
                "cannot bootstrap accounts before the Anonymous PGC protocol is active",
            ));
        };
        if current_height < active.state_since_height {
            return Err(invalid_privacy_parameter(format!(
                "Anonymous PGC activation is not effective until block {}",
                active.state_since_height
            )));
        }
        let head_key =
            PrivacyRootHeadKeyV1::new(self.bootstrap.namespace, PrivacyRootRoleV1::PgcAccountState)
                .map_err(invalid_privacy_parameter)?;
        let invariant_key = PrivacyPgcPoolInvariantKeyV1::new(self.bootstrap.namespace)
            .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "Anonymous PGC account state is already initialized",
            ));
        }
        if state_transaction
            .world
            .privacy_pgc_pool_invariants
            .get(&invariant_key)
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "Anonymous PGC pool invariant exists without a current head".into(),
            ));
        }
        if state_transaction
            .world
            .privacy_roots
            .range(PrivacyRootKeyV1::history_range(
                self.bootstrap.namespace,
                PrivacyRootRoleV1::PgcAccountState,
            ))
            .next()
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "Anonymous PGC root history exists without a current head".into(),
            ));
        }
        if state_transaction
            .world
            .privacy_pgc_accounts
            .range(PrivacyPgcAccountKeyV1::pool_range(self.bootstrap.namespace))
            .next()
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "Anonymous PGC accounts exist without a current head".into(),
            ));
        }
        let computed_root = compute_privacy_pgc_account_state_root_v1(
            self.bootstrap.namespace,
            self.bootstrap.initial_epoch,
            self.bootstrap.total_supply,
            &self.bootstrap.accounts,
        )
        .map_err(invalid_privacy_parameter)?;
        if computed_root != self.bootstrap.initial_root {
            return Err(invalid_privacy_parameter(
                "privacy PGC bootstrap root does not match the canonical account table",
            ));
        }
        let bootstrap_digest = self.bootstrap.digest().map_err(|error| {
            Error::InvariantViolation(
                format!("privacy PGC bootstrap canonical encoding failed: {error}").into(),
            )
        })?;
        let namespace_encoding =
            norito::encode_canonical(&self.bootstrap.namespace).map_err(|error| {
                Error::InvariantViolation(
                    format!("privacy PGC namespace canonical encoding failed: {error}").into(),
                )
            })?;
        let native_public_keys = self
            .bootstrap
            .accounts
            .iter()
            .map(|account| {
                TwistedElGamalPublicKeyV1::from_sec1_bytes(account.public_key.as_bytes())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "privacy PGC bootstrap public key rejected: {error}"
                ))
            })?;
        let native_balances = self
            .bootstrap
            .accounts
            .iter()
            .map(|account| {
                TwistedElGamalCiphertextV1::from_sec1_bytes(
                    account.encrypted_balance.left.as_bytes(),
                    account.encrypted_balance.right.as_bytes(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "privacy PGC bootstrap ciphertext rejected: {error}"
                ))
            })?;
        let genesis_hash = state_transaction
            .block_hashes()
            .first()
            .map(|hash| *hash.as_ref())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "privacy PGC bootstrap requires a committed genesis block".into(),
                )
            })?;
        let parameters = AnonymousPgcParametersV1::get().map_err(|error| {
            Error::InvariantViolation(
                format!("native Anonymous PGC parameters are unavailable: {error}").into(),
            )
        })?;
        let native_statement = AnonymousPgcBootstrapStatementV1::new(
            &namespace_encoding,
            *self.bootstrap.initial_root.as_bytes(),
            self.bootstrap.initial_epoch,
            self.bootstrap.total_supply,
            &native_public_keys,
            &native_balances,
            TranscriptBindingV1 {
                network_id: state_transaction.network_id.as_bytes(),
                genesis_hash,
                action_index: expected_action_index,
                statement_digest: *bootstrap_digest.as_bytes(),
                parameter_id: *activation.parameter_id.as_bytes(),
                parameter_digest: *activation.parameter_digest.as_bytes(),
                verifier_digest: *activation.verifier_digest.as_bytes(),
                statement_schema_digest: *activation.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *activation.engine_manifest_digest.as_bytes(),
                generator_digest: parameters.generator_digest(),
            },
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("privacy PGC bootstrap statement rejected: {error}"))
        })?;
        let verified = verify_bootstrap_encoded(&native_statement, self.proof.as_bytes()).map_err(
            |error| {
                invalid_privacy_parameter(format!(
                    "privacy PGC bootstrap proof verification failed: {error}"
                ))
            },
        )?;
        if verified.total_supply() != self.bootstrap.total_supply
            || verified.account_count() != self.bootstrap.accounts.len()
            || verified.bootstrap_table_digest() != native_statement.bootstrap_table_digest()
        {
            return Err(Error::InvariantViolation(
                "native PGC bootstrap verifier returned inconsistent effects".into(),
            ));
        }
        let bootstrap_proof_digest = self.proof.digest().map_err(|error| {
            Error::InvariantViolation(
                format!("verified PGC bootstrap proof digest failed: {error}").into(),
            )
        })?;
        let pool_invariant = PrivacyPgcPoolInvariantV1::new(
            self.bootstrap.total_supply,
            self.bootstrap.initial_root,
            bootstrap_digest,
            bootstrap_proof_digest,
        )
        .map_err(invalid_privacy_parameter)?;
        let account_provenance = PrivacyPgcAccountProvenanceV1::bootstrap(
            bootstrap_digest,
            bootstrap_proof_digest,
            current_height,
        )
        .map_err(invalid_privacy_parameter)?;
        let mut account_updates = Vec::with_capacity(self.bootstrap.accounts.len());
        for account in &self.bootstrap.accounts {
            let key = PrivacyPgcAccountKeyV1::new(self.bootstrap.namespace, account.public_key)
                .map_err(invalid_privacy_parameter)?;
            let state = PrivacyPgcAccountStateV1::new(
                account.encrypted_balance,
                self.bootstrap.initial_epoch,
                account_provenance,
            )
            .map_err(invalid_privacy_parameter)?;
            account_updates.push((key, state));
        }
        let root_provenance = PrivacyRootProvenanceV1::verified_bootstrap(
            bootstrap_digest,
            bootstrap_proof_digest,
            current_height,
        )
        .map_err(invalid_privacy_parameter)?;
        let root_key = PrivacyRootKeyV1::new(
            self.bootstrap.namespace,
            PrivacyRootRoleV1::PgcAccountState,
            self.bootstrap.initial_epoch,
            self.bootstrap.initial_root,
        )
        .map_err(invalid_privacy_parameter)?;
        let root_head = PrivacyRootHeadRecordV1::new(
            self.bootstrap.initial_epoch,
            self.bootstrap.initial_root,
            root_provenance,
            None,
        )
        .map_err(invalid_privacy_parameter)?;
        let removals = plan_privacy_root_history_update_v1(
            &state_transaction.world.privacy_roots,
            &[root_key],
            state_transaction
                .world
                .privacy_consensus_policy
                .get()
                .current_limits
                .retained_root_count,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("privacy PGC bootstrap root rejected: {error}"))
        })?;
        if !removals.is_empty() {
            return Err(Error::InvariantViolation(
                "new Anonymous PGC root history unexpectedly requires pruning".into(),
            ));
        }
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_pgc_pool_invariants
            .insert(invariant_key, pool_invariant);
        for (key, state) in account_updates {
            state_transaction
                .world
                .privacy_pgc_accounts
                .insert(key, state);
        }
        state_transaction
            .world
            .privacy_roots
            .insert(root_key, root_provenance);
        state_transaction
            .world
            .privacy_root_heads
            .insert(head_key, root_head);
        Ok(())
    }
}
fn validate_zk_ace_policy_references(
    policy: &iroha_data_model::privacy::PrivacyZkAcePolicyRecordV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    state_transaction
        .world
        .asset_definition(&policy.asset_definition_id)
        .map_err(Error::from)?;
    for account_id in &policy.source_allowlist {
        if state_transaction.world.accounts.get(account_id).is_none() {
            return Err(invalid_privacy_parameter(format!(
                "ZK-ACE source account `{account_id}` does not exist"
            )));
        }
    }
    Ok(())
}
struct PlannedZkX509RootAppendV1 {
    root_key: PrivacyRootKeyV1,
    provenance: PrivacyRootProvenanceV1,
    head_key: PrivacyRootHeadKeyV1,
    next_head: PrivacyRootHeadRecordV1,
    removals: Vec<PrivacyRootKeyV1>,
}
#[expect(
    clippy::large_types_passed_by_value,
    reason = "the validated provenance becomes the owned root-head record"
)]
fn plan_zk_x509_root_append_v1(
    publication: PrivacyRootPublicationV1,
    provenance: PrivacyRootProvenanceV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<PlannedZkX509RootAppendV1, Error> {
    publication.validate().map_err(|error| {
        invalid_privacy_parameter(format!("X.509 root publication rejected: {error}"))
    })?;
    provenance
        .validate()
        .map_err(|error| invalid_privacy_parameter(format!("invalid X.509 provenance: {error}")))?;
    let root_key = PrivacyRootKeyV1::new(
        publication.namespace,
        publication.role,
        publication.epoch,
        publication.root,
    )
    .map_err(invalid_privacy_parameter)?;
    let head_key = PrivacyRootHeadKeyV1::new(publication.namespace, publication.role)
        .map_err(invalid_privacy_parameter)?;
    let current_head = state_transaction
        .world
        .privacy_root_heads
        .get(&head_key)
        .copied();
    match current_head {
        None if publication.epoch != 1 => {
            return Err(invalid_privacy_parameter(
                "initial X.509 root publication must use epoch one",
            ));
        }
        Some(head) => {
            head.validate().map_err(|error| {
                Error::InvariantViolation(
                    format!("persisted X.509 root head is invalid: {error}").into(),
                )
            })?;
            let expected_epoch = head.epoch().checked_add(1).ok_or_else(|| {
                invalid_privacy_parameter("X.509 root epoch cannot advance past u64::MAX")
            })?;
            if publication.epoch != expected_epoch {
                return Err(invalid_privacy_parameter(format!(
                    "X.509 root epoch must advance exactly from {} to {expected_epoch}",
                    head.epoch()
                )));
            }
            let retained_head = PrivacyRootKeyV1::new(
                head_key.namespace(),
                head_key.role(),
                head.epoch(),
                head.root(),
            )
            .map_err(invalid_privacy_parameter)?;
            if state_transaction.world.privacy_roots.get(&retained_head) != Some(&head.provenance())
            {
                return Err(Error::InvariantViolation(
                    "X.509 root head is inconsistent with retained history".into(),
                ));
            }
        }
        None => {
            if state_transaction
                .world
                .privacy_roots
                .range(PrivacyRootKeyV1::history_range(
                    head_key.namespace(),
                    head_key.role(),
                ))
                .next()
                .is_some()
            {
                return Err(Error::InvariantViolation(
                    "X.509 root history exists without a current head".into(),
                ));
            }
        }
    }
    let removals = plan_privacy_root_history_update_v1(
        &state_transaction.world.privacy_roots,
        &[root_key],
        state_transaction
            .world
            .privacy_consensus_policy
            .get()
            .admission_retained_root_count(),
    )
    .map_err(|error| {
        invalid_privacy_parameter(format!("X.509 root publication rejected: {error}"))
    })?;
    let retention_anchor = removals
        .last()
        .map(|key| PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root()))
        .transpose()
        .map_err(invalid_privacy_parameter)?
        .or_else(|| current_head.and_then(PrivacyRootHeadRecordV1::retention_anchor));
    let next_head = PrivacyRootHeadRecordV1::new(
        publication.epoch,
        publication.root,
        provenance,
        retention_anchor,
    )
    .map_err(invalid_privacy_parameter)?;
    Ok(PlannedZkX509RootAppendV1 {
        root_key,
        provenance,
        head_key,
        next_head,
        removals,
    })
}
fn plan_zk_x509_ca_root_append_v1(
    record: PrivacyZkX509TrustAnchorRecordV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<PlannedZkX509RootAppendV1, Error> {
    let namespace = privacy_zk_x509_ca_namespace_v1(record.trust_anchor_id)
        .map_err(invalid_privacy_parameter)?;
    let publication = PrivacyRootPublicationV1::new(
        namespace,
        PrivacyRootRoleV1::CertificateAuthorityMembership,
        record.ca_membership_root_epoch,
        record.ca_membership_root,
    )
    .map_err(|error| invalid_privacy_parameter(error.to_string()))?;
    let publication_digest = publication.digest().map_err(|error| {
        invalid_privacy_parameter(format!(
            "X.509 CA-root publication encoding failed: {error}"
        ))
    })?;
    let provenance = PrivacyRootProvenanceV1::zk_x509_ca_governance(
        publication_digest,
        publication.namespace,
        publication.epoch,
        publication.root,
        record,
        state_transaction.block_height(),
    )
    .map_err(invalid_privacy_parameter)?;
    plan_zk_x509_root_append_v1(publication, provenance, state_transaction)
}
fn apply_zk_x509_root_append_v1(
    plan: PlannedZkX509RootAppendV1,
    state_transaction: &mut StateTransaction<'_, '_>,
) {
    for key in plan.removals {
        state_transaction.world.privacy_roots.remove(key);
    }
    state_transaction
        .world
        .privacy_roots
        .insert(plan.root_key, plan.provenance);
    state_transaction
        .world
        .privacy_root_heads
        .insert(plan.head_key, plan.next_head);
}
// TODO(X.6): take this verdict from the canonical interval definition
// (`PrivacyZkX509PresentationBoundsV1::from_crl(record.update_interval())`
// containing the block second). The predicate below is the same on every block
// second within the RFC 5280 calendar; it is pinned as a `deferred` site in
// specs/zk_x509_presentation_interval_sites.json and compared with the
// definition by `deferred_sites_equal_the_canonical_definition_on_a_boundary_grid`.
fn validate_zk_x509_crl_freshness_v1(
    record: PrivacyZkX509CrlRecordV1,
    block_timestamp_ms: u64,
) -> Result<(), Error> {
    let block_unix_seconds = block_timestamp_ms / 1_000;
    if block_unix_seconds < record.this_update_unix_seconds
        || block_unix_seconds >= record.next_update_unix_seconds
    {
        return Err(invalid_privacy_parameter(
            "X.509 signed CRL is not current at the executing block timestamp",
        ));
    }
    let age = block_unix_seconds
        .checked_sub(record.this_update_unix_seconds)
        .ok_or_else(|| invalid_privacy_parameter("X.509 signed CRL begins in the future"))?;
    if age > ZK_X509_MAX_CRL_AGE_SECONDS_V1 {
        return Err(invalid_privacy_parameter(format!(
            "X.509 signed CRL age {age}s exceeds the {ZK_X509_MAX_CRL_AGE_SECONDS_V1}s freshness limit"
        )));
    }
    Ok(())
}
fn validate_current_zk_x509_ca_root_v1(
    trust_anchor: PrivacyZkX509TrustAnchorRecordV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    validate_privacy_zk_x509_trust_anchor_root_state_v1(
        trust_anchor,
        state_transaction
            .world
            .privacy_consensus_policy
            .get()
            .admission_retained_root_count(),
        &state_transaction.world.privacy_roots,
        &state_transaction.world.privacy_root_heads,
    )
    .map_err(|error| {
        Error::InvariantViolation(
            format!("persisted X.509 CA-root state is invalid: {error}").into(),
        )
    })
}
fn preflight_x509_governance_action_v1<T: norito::NoritoSerialize>(
    instruction: &T,
    label: &str,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(u32, u64), Error> {
    let encoded_action_bytes = norito::canonical_frame_len(instruction)
        .ok()
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| {
            Error::InvariantViolation(format!("{label} canonical encoding failed").into())
        })?;
    let expected_action_index = state_transaction.next_privacy_action_index();
    state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
    Ok((expected_action_index, encoded_action_bytes))
}
fn x509_trust_anchor_lineage_revision_count_v1(
    trust_anchor_id: iroha_data_model::privacy::PrivacyIssuerIdV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<usize, Error> {
    let mut count = 0usize;
    for _ in state_transaction.world.privacy_commitments.range(
        PrivacyCommitmentKeyV1::zk_x509_trust_anchor_lineage_range(trust_anchor_id),
    ) {
        count = count.checked_add(1).ok_or_else(|| {
            Error::InvariantViolation("X.509 trust-anchor lineage count overflow".into())
        })?;
        if count > ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(Error::InvariantViolation(
                "persisted X.509 trust-anchor lineage exceeds its revision cap".into(),
            ));
        }
    }
    Ok(count)
}
fn x509_certificate_policy_lineage_revision_count_v1(
    trust_anchor_id: iroha_data_model::privacy::PrivacyIssuerIdV1,
    policy_id: iroha_data_model::privacy::PrivacyPolicyIdV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<usize, Error> {
    let mut count = 0usize;
    for _ in state_transaction.world.privacy_commitments.range(
        PrivacyCommitmentKeyV1::zk_x509_certificate_policy_lineage_range(
            trust_anchor_id,
            policy_id,
        ),
    ) {
        count = count.checked_add(1).ok_or_else(|| {
            Error::InvariantViolation("X.509 certificate-policy lineage count overflow".into())
        })?;
        if count > ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(Error::InvariantViolation(
                "persisted X.509 certificate-policy lineage exceeds its revision cap".into(),
            ));
        }
    }
    Ok(count)
}
fn require_registered_zk_ace_protocol(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let activation_key = PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::ZkAcePqAuthorizationV1);
    let activation = state_transaction
        .world
        .privacy_activations
        .get(&activation_key)
        .ok_or_else(|| invalid_privacy_parameter("ZK-ACE privacy protocol is not registered"))?;
    activation.validate().map_err(|error| {
        Error::InvariantViolation(
            format!("registered ZK-ACE activation is invalid: {error}").into(),
        )
    })?;
    validate_compiled_privacy_activation_v1(activation).map_err(|error| {
        Error::InvariantViolation(
            format!("registered ZK-ACE activation is not executable: {error}").into(),
        )
    })
}
fn require_registered_bootle_lantern_protocol(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let protocol_id = PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1;
    let activation = state_transaction
        .world
        .privacy_activations
        .get(&PrivacyActivationKeyV1::new(protocol_id))
        .ok_or_else(|| {
            invalid_privacy_parameter("Bootle/Lantern privacy protocol is not registered")
        })?;
    if activation.protocol_id != protocol_id {
        return Err(Error::InvariantViolation(
            "registered Bootle/Lantern activation has a mismatched protocol id".into(),
        ));
    }
    activation.validate().map_err(|error| {
        Error::InvariantViolation(
            format!("registered Bootle/Lantern activation is invalid: {error}").into(),
        )
    })?;
    validate_compiled_privacy_activation_v1(activation).map_err(|error| {
        Error::InvariantViolation(
            format!("registered Bootle/Lantern activation is not executable: {error}").into(),
        )
    })
}
fn require_registered_vega_protocol(
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
    let activation = state_transaction
        .world
        .privacy_activations
        .get(&PrivacyActivationKeyV1::new(protocol_id))
        .ok_or_else(|| invalid_privacy_parameter("Vega privacy protocol is not registered"))?;
    if activation.protocol_id != protocol_id {
        return Err(Error::InvariantViolation(
            "registered Vega activation has a mismatched protocol id".into(),
        ));
    }
    activation.validate().map_err(|error| {
        Error::InvariantViolation(format!("registered Vega activation is invalid: {error}").into())
    })?;
    validate_compiled_privacy_activation_v1(activation).map_err(|error| {
        Error::InvariantViolation(
            format!("registered Vega activation is not executable: {error}").into(),
        )
    })
}
impl Execute for RegisterPrivacyZkX509TrustAnchorV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 trust-anchor registration",
            state_transaction,
        )?;
        self.record.validate_initial().map_err(|error| {
            invalid_privacy_parameter(format!("X.509 trust-anchor registration rejected: {error}"))
        })?;
        let (trust_anchor_count, _) = privacy_zk_x509_governance_record_counts_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted X.509 governance state is invalid: {error}").into(),
            )
        })?;
        if trust_anchor_count >= ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 trust-anchor registry is full at {ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1} revisions"
            )));
        }
        if x509_trust_anchor_lineage_revision_count_v1(
            self.record.trust_anchor_id,
            state_transaction,
        )? != 0
        {
            return Err(invalid_privacy_parameter(
                "X.509 trust-anchor lineage is already registered",
            ));
        }
        let key = PrivacyCommitmentKeyV1::zk_x509_trust_anchor_revision(
            self.record.trust_anchor_id,
            self.record.record_epoch,
        )
        .map_err(invalid_privacy_parameter)?;
        let state_record = PrivacyStateItemRecordV1::zk_x509_trust_anchor_governance(
            self.record,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        let root_plan = plan_zk_x509_ca_root_append_v1(self.record, state_transaction)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        apply_zk_x509_root_append_v1(root_plan, state_transaction);
        Ok(())
    }
}
impl Execute for RotatePrivacyZkX509TrustAnchorV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 trust-anchor rotation",
            state_transaction,
        )?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "X.509 expected current trust-anchor digest must be non-zero",
            ));
        }
        let (trust_anchor_count, _) = privacy_zk_x509_governance_record_counts_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted X.509 governance state is invalid: {error}").into(),
            )
        })?;
        if trust_anchor_count >= ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 trust-anchor registry is full at {ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1} revisions"
            )));
        }
        let lineage_count = x509_trust_anchor_lineage_revision_count_v1(
            self.successor.trust_anchor_id,
            state_transaction,
        )?;
        if lineage_count >= ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 trust-anchor lineage is full at {ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1} revisions"
            )));
        }
        let current = load_privacy_zk_x509_trust_anchor_v1(
            self.successor.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("X.509 trust-anchor rotation rejected: {error}"))
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "X.509 trust-anchor rotation expected a stale or substituted current revision",
            ));
        }
        validate_zk_x509_trust_anchor_rotation_v1(&current, &self.successor).map_err(|error| {
            invalid_privacy_parameter(format!("X.509 trust-anchor rotation rejected: {error}"))
        })?;
        let key = PrivacyCommitmentKeyV1::zk_x509_trust_anchor_revision(
            self.successor.trust_anchor_id,
            self.successor.record_epoch,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "X.509 trust-anchor successor revision already exists",
            ));
        }
        let state_record = PrivacyStateItemRecordV1::zk_x509_trust_anchor_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        let root_plan = plan_zk_x509_ca_root_append_v1(self.successor, state_transaction)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        apply_zk_x509_root_append_v1(root_plan, state_transaction);
        Ok(())
    }
}
impl Execute for RevokePrivacyZkX509TrustAnchorV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 trust-anchor revocation",
            state_transaction,
        )?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "X.509 expected current trust-anchor digest must be non-zero",
            ));
        }
        let (trust_anchor_count, _) = privacy_zk_x509_governance_record_counts_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted X.509 governance state is invalid: {error}").into(),
            )
        })?;
        if trust_anchor_count >= ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 trust-anchor registry is full at {ZK_X509_MAX_TRUST_ANCHOR_RECORDS_V1} revisions"
            )));
        }
        let lineage_count = x509_trust_anchor_lineage_revision_count_v1(
            self.successor.trust_anchor_id,
            state_transaction,
        )?;
        if lineage_count >= ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 trust-anchor lineage is full at {ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1} revisions"
            )));
        }
        let current = load_privacy_zk_x509_trust_anchor_v1(
            self.successor.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("X.509 trust-anchor revocation rejected: {error}"))
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "X.509 trust-anchor revocation expected a stale or substituted current revision",
            ));
        }
        validate_zk_x509_trust_anchor_revocation_v1(&current, &self.successor).map_err(
            |error| {
                invalid_privacy_parameter(format!(
                    "X.509 trust-anchor revocation rejected: {error}"
                ))
            },
        )?;
        validate_privacy_zk_x509_trust_anchor_revocation_dependencies_v1(
            self.successor.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("X.509 trust-anchor revocation rejected: {error}"))
        })?;
        let key = PrivacyCommitmentKeyV1::zk_x509_trust_anchor_revision(
            self.successor.trust_anchor_id,
            self.successor.record_epoch,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "X.509 trust-anchor successor revision already exists",
            ));
        }
        let state_record = PrivacyStateItemRecordV1::zk_x509_trust_anchor_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RegisterPrivacyZkX509CertificatePolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 certificate-policy registration",
            state_transaction,
        )?;
        self.record.validate_initial().map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy registration rejected: {error}"
            ))
        })?;
        let (_, policy_count) = privacy_zk_x509_governance_record_counts_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted X.509 governance state is invalid: {error}").into(),
            )
        })?;
        if policy_count >= ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 certificate-policy registry is full at {ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1} revisions"
            )));
        }
        let trust_anchor = load_privacy_zk_x509_trust_anchor_v1(
            self.record.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy registration requires a trust anchor: {error}"
            ))
        })?;
        if trust_anchor.lifecycle != PrivacyZkX509RecordLifecycleV1::Active {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy registration requires an active trust anchor",
            ));
        }
        validate_current_zk_x509_ca_root_v1(trust_anchor, state_transaction)?;
        if x509_certificate_policy_lineage_revision_count_v1(
            self.record.trust_anchor_id,
            self.record.policy_id,
            state_transaction,
        )? != 0
        {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy lineage is already registered",
            ));
        }
        let key = PrivacyCommitmentKeyV1::zk_x509_certificate_policy_revision(
            self.record.trust_anchor_id,
            self.record.policy_id,
            self.record.record_epoch,
        )
        .map_err(invalid_privacy_parameter)?;
        let state_record = PrivacyStateItemRecordV1::zk_x509_certificate_policy_governance(
            self.record,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RotatePrivacyZkX509CertificatePolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 certificate-policy rotation",
            state_transaction,
        )?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "X.509 expected current certificate-policy digest must be non-zero",
            ));
        }
        let (_, policy_count) = privacy_zk_x509_governance_record_counts_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted X.509 governance state is invalid: {error}").into(),
            )
        })?;
        if policy_count >= ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 certificate-policy registry is full at {ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1} revisions"
            )));
        }
        let trust_anchor = load_privacy_zk_x509_trust_anchor_v1(
            self.successor.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy rotation requires a trust anchor: {error}"
            ))
        })?;
        if trust_anchor.lifecycle != PrivacyZkX509RecordLifecycleV1::Active {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy rotation requires an active trust anchor",
            ));
        }
        validate_current_zk_x509_ca_root_v1(trust_anchor, state_transaction)?;
        let lineage_count = x509_certificate_policy_lineage_revision_count_v1(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            state_transaction,
        )?;
        if lineage_count >= ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 certificate-policy lineage is full at {ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1} revisions"
            )));
        }
        let current = load_privacy_zk_x509_certificate_policy_v1(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy rotation rejected: {error}"
            ))
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy rotation expected a stale or substituted current revision",
            ));
        }
        validate_zk_x509_certificate_policy_rotation_v1(&current, &self.successor).map_err(
            |error| {
                invalid_privacy_parameter(format!(
                    "X.509 certificate-policy rotation rejected: {error}"
                ))
            },
        )?;
        let key = PrivacyCommitmentKeyV1::zk_x509_certificate_policy_revision(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            self.successor.record_epoch,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy successor revision already exists",
            ));
        }
        let state_record = PrivacyStateItemRecordV1::zk_x509_certificate_policy_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RevokePrivacyZkX509CertificatePolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 certificate-policy revocation",
            state_transaction,
        )?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "X.509 expected current certificate-policy digest must be non-zero",
            ));
        }
        let (_, policy_count) = privacy_zk_x509_governance_record_counts_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted X.509 governance state is invalid: {error}").into(),
            )
        })?;
        if policy_count >= ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 certificate-policy registry is full at {ZK_X509_MAX_CERTIFICATE_POLICY_RECORDS_V1} revisions"
            )));
        }
        load_privacy_zk_x509_trust_anchor_v1(
            self.successor.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy revocation requires a trust anchor: {error}"
            ))
        })?;
        let lineage_count = x509_certificate_policy_lineage_revision_count_v1(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            state_transaction,
        )?;
        if lineage_count >= ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 certificate-policy lineage is full at {ZK_X509_MAX_RECORD_REVISIONS_PER_LINEAGE_V1} revisions"
            )));
        }
        let current = load_privacy_zk_x509_certificate_policy_v1(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy revocation rejected: {error}"
            ))
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy revocation expected a stale or substituted current revision",
            ));
        }
        validate_zk_x509_certificate_policy_revocation_v1(&current, &self.successor).map_err(
            |error| {
                invalid_privacy_parameter(format!(
                    "X.509 certificate-policy revocation rejected: {error}"
                ))
            },
        )?;
        validate_privacy_zk_x509_policy_revocation_dependencies_v1(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 certificate-policy revocation rejected: {error}"
            ))
        })?;
        let key = PrivacyCommitmentKeyV1::zk_x509_certificate_policy_revision(
            self.successor.trust_anchor_id,
            self.successor.policy_id,
            self.successor.record_epoch,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "X.509 certificate-policy successor revision already exists",
            ));
        }
        let state_record = PrivacyStateItemRecordV1::zk_x509_certificate_policy_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RegisterPrivacyZkX509CrlV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 signed-CRL registration",
            state_transaction,
        )?;
        self.record.validate_initial().map_err(|error| {
            invalid_privacy_parameter(format!("X.509 signed-CRL registration rejected: {error}"))
        })?;
        let crl_lineage_count =
            privacy_zk_x509_crl_lineage_count_v1(&state_transaction.world.privacy_commitments)
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("persisted X.509 governance state is invalid: {error}").into(),
                    )
                })?;
        if crl_lineage_count >= ZK_X509_MAX_CRL_LINEAGES_V1 {
            return Err(invalid_privacy_parameter(format!(
                "X.509 signed-CRL registry is full at {ZK_X509_MAX_CRL_LINEAGES_V1} lineages"
            )));
        }
        let trust_anchor = load_privacy_zk_x509_trust_anchor_v1(
            self.record.trust_anchor_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 signed-CRL registration requires a trust anchor: {error}"
            ))
        })?;
        if trust_anchor.lifecycle != PrivacyZkX509RecordLifecycleV1::Active {
            return Err(invalid_privacy_parameter(
                "X.509 signed-CRL registration requires an active trust anchor",
            ));
        }
        validate_current_zk_x509_ca_root_v1(trust_anchor, state_transaction)?;
        let certificate_policy = load_privacy_zk_x509_certificate_policy_v1(
            self.record.trust_anchor_id,
            self.record.certificate_policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!(
                "X.509 signed-CRL registration requires a certificate policy: {error}"
            ))
        })?;
        if certificate_policy.lifecycle != PrivacyZkX509RecordLifecycleV1::Active {
            return Err(invalid_privacy_parameter(
                "X.509 signed-CRL registration requires an active certificate policy",
            ));
        }
        validate_zk_x509_crl_freshness_v1(
            self.record,
            state_transaction.block_unix_timestamp_ms(),
        )?;
        let key = PrivacyCommitmentKeyV1::zk_x509_crl_current(
            self.record.trust_anchor_id,
            self.record.certificate_policy_id,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "X.509 signed-CRL lineage is already registered",
            ));
        }
        let state_record = PrivacyStateItemRecordV1::zk_x509_crl_governance(
            self.record,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RotatePrivacyZkX509CrlV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 signed-CRL rotation",
            state_transaction,
        )?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "X.509 expected current signed-CRL digest must be non-zero",
            ));
        }
        let retained_root_count = state_transaction
            .world
            .privacy_consensus_policy
            .get()
            .admission_retained_root_count();
        let authoritative = load_privacy_zk_x509_authoritative_state_v1(
            self.successor.trust_anchor_id,
            self.successor.certificate_policy_id,
            retained_root_count,
            &state_transaction.world.privacy_commitments,
            &state_transaction.world.privacy_roots,
            &state_transaction.world.privacy_root_heads,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("X.509 signed-CRL rotation rejected: {error}"))
        })?;
        let current = authoritative.crl_record();
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "X.509 signed-CRL rotation expected a stale or substituted current revision",
            ));
        }
        validate_zk_x509_crl_rotation_v1(&current, &self.successor).map_err(|error| {
            invalid_privacy_parameter(format!("X.509 signed-CRL rotation rejected: {error}"))
        })?;
        validate_zk_x509_crl_freshness_v1(
            self.successor,
            state_transaction.block_unix_timestamp_ms(),
        )?;
        let key = PrivacyCommitmentKeyV1::zk_x509_crl_current(
            self.successor.trust_anchor_id,
            self.successor.certificate_policy_id,
        )
        .map_err(invalid_privacy_parameter)?;
        let state_record = PrivacyStateItemRecordV1::zk_x509_crl_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RevokePrivacyZkX509CrlV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let (expected_action_index, encoded_action_bytes) = preflight_x509_governance_action_v1(
            &self,
            "X.509 signed-CRL revocation",
            state_transaction,
        )?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "X.509 expected current signed-CRL digest must be non-zero",
            ));
        }
        let retained_root_count = state_transaction
            .world
            .privacy_consensus_policy
            .get()
            .admission_retained_root_count();
        let authoritative = load_privacy_zk_x509_authoritative_state_v1(
            self.successor.trust_anchor_id,
            self.successor.certificate_policy_id,
            retained_root_count,
            &state_transaction.world.privacy_commitments,
            &state_transaction.world.privacy_roots,
            &state_transaction.world.privacy_root_heads,
        )
        .map_err(|error| {
            invalid_privacy_parameter(format!("X.509 signed-CRL revocation rejected: {error}"))
        })?;
        let current = authoritative.crl_record();
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "X.509 signed-CRL revocation expected a stale or substituted current revision",
            ));
        }
        validate_zk_x509_crl_revocation_v1(&current, &self.successor).map_err(|error| {
            invalid_privacy_parameter(format!("X.509 signed-CRL revocation rejected: {error}"))
        })?;
        let key = PrivacyCommitmentKeyV1::zk_x509_crl_current(
            self.successor.trust_anchor_id,
            self.successor.certificate_policy_id,
        )
        .map_err(invalid_privacy_parameter)?;
        let state_record = PrivacyStateItemRecordV1::zk_x509_crl_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, state_record);
        Ok(())
    }
}
impl Execute for RegisterPrivacyZkAcePolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "ZK-ACE policy registration canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_zk_ace_protocol(state_transaction)?;
        self.policy.validate_initial().map_err(|error| {
            invalid_privacy_parameter(format!("ZK-ACE policy registration rejected: {error}"))
        })?;
        validate_zk_ace_policy_references(&self.policy, state_transaction)?;
        let policy_count = privacy_zk_ace_policy_count_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted ZK-ACE policy registry is invalid: {error}").into(),
            )
        })?;
        if policy_count >= PRIVACY_ZK_ACE_MAX_POLICIES_V1 {
            return Err(invalid_privacy_parameter(format!(
                "ZK-ACE policy registry is full at {PRIVACY_ZK_ACE_MAX_POLICIES_V1} policies"
            )));
        }
        let key = PrivacyCommitmentKeyV1::zk_ace_policy(self.policy.policy_id)
            .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "ZK-ACE policy id is already registered",
            ));
        }
        let record = PrivacyStateItemRecordV1::zk_ace_policy_governance(
            self.policy,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, record);
        Ok(())
    }
}
impl Execute for RotatePrivacyZkAcePolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation("ZK-ACE policy rotation canonical encoding failed".into())
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_zk_ace_protocol(state_transaction)?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "ZK-ACE expected current policy digest must be non-zero",
            ));
        }
        let current = load_privacy_zk_ace_policy_v1(
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("trusted ZK-ACE policy state failed validation: {error}").into(),
            )
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "ZK-ACE policy rotation expected a stale or substituted current record",
            ));
        }
        validate_zk_ace_policy_rotation_v1(&current, &self.successor).map_err(|error| {
            invalid_privacy_parameter(format!("ZK-ACE policy rotation rejected: {error}"))
        })?;
        validate_zk_ace_policy_references(&self.successor, state_transaction)?;
        let key = PrivacyCommitmentKeyV1::zk_ace_policy(current.policy_id)
            .map_err(invalid_privacy_parameter)?;
        let record = PrivacyStateItemRecordV1::zk_ace_policy_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, record);
        Ok(())
    }
}
impl Execute for RevokePrivacyZkAcePolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "ZK-ACE policy revocation canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_zk_ace_protocol(state_transaction)?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "ZK-ACE expected current policy digest must be non-zero",
            ));
        }
        let current = load_privacy_zk_ace_policy_v1(
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("trusted ZK-ACE policy state failed validation: {error}").into(),
            )
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "ZK-ACE policy revocation expected a stale or substituted current record",
            ));
        }
        validate_zk_ace_policy_revocation_v1(&current, &self.successor).map_err(|error| {
            invalid_privacy_parameter(format!("ZK-ACE policy revocation rejected: {error}"))
        })?;
        if self.successor.lifecycle != PrivacyZkAcePolicyLifecycleV1::Revoked {
            return Err(invalid_privacy_parameter(
                "ZK-ACE policy revocation successor must be revoked",
            ));
        }
        let key = PrivacyCommitmentKeyV1::zk_ace_policy(current.policy_id)
            .map_err(invalid_privacy_parameter)?;
        let record = PrivacyStateItemRecordV1::zk_ace_policy_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, record);
        Ok(())
    }
}
impl Execute for RegisterPrivacyBootleLanternIssuerPolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "Bootle/Lantern issuer-policy registration canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_bootle_lantern_protocol(state_transaction)?;
        self.policy.validate_initial().map_err(|error| {
            invalid_privacy_parameter(format!(
                "Bootle/Lantern issuer-policy registration rejected: {error}"
            ))
        })?;
        let policy_count = privacy_bootle_lantern_issuer_policy_count_v1(
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("persisted Bootle/Lantern issuer-policy registry is invalid: {error}")
                    .into(),
            )
        })?;
        if policy_count >= BOOTLE_LANTERN_MAX_ISSUER_POLICIES_V1 {
            return Err(invalid_privacy_parameter(format!(
                "Bootle/Lantern issuer-policy registry is full at {BOOTLE_LANTERN_MAX_ISSUER_POLICIES_V1} policies"
            )));
        }
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            self.policy.issuer_id,
            self.policy.policy_id,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_some()
        {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern issuer policy is already registered",
            ));
        }
        let record = PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(
            self.policy,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, record);
        Ok(())
    }
}
impl Execute for RotatePrivacyBootleLanternIssuerPolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "Bootle/Lantern issuer-policy rotation canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_bootle_lantern_protocol(state_transaction)?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern expected current issuer-policy digest must be non-zero",
            ));
        }
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            self.successor.issuer_id,
            self.successor.policy_id,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_none()
        {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern issuer policy is not registered",
            ));
        }
        let current = load_privacy_bootle_lantern_issuer_policy_v1(
            self.successor.issuer_id,
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("trusted Bootle/Lantern issuer-policy state failed validation: {error}")
                    .into(),
            )
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern issuer-policy rotation expected a stale or substituted current record",
            ));
        }
        self.successor
            .validate_rotation_successor(&current)
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "Bootle/Lantern issuer-policy rotation rejected: {error}"
                ))
            })?;
        let record = PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, record);
        Ok(())
    }
}
impl Execute for RevokePrivacyBootleLanternIssuerPolicyV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "Bootle/Lantern issuer-policy revocation canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_bootle_lantern_protocol(state_transaction)?;
        if self.expected_current_record_digest.is_zero() {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern expected current issuer-policy digest must be non-zero",
            ));
        }
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            self.successor.issuer_id,
            self.successor.policy_id,
        )
        .map_err(invalid_privacy_parameter)?;
        if state_transaction
            .world
            .privacy_commitments
            .get(&key)
            .is_none()
        {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern issuer policy is not registered",
            ));
        }
        let current = load_privacy_bootle_lantern_issuer_policy_v1(
            self.successor.issuer_id,
            self.successor.policy_id,
            &state_transaction.world.privacy_commitments,
        )
        .map_err(|error| {
            Error::InvariantViolation(
                format!("trusted Bootle/Lantern issuer-policy state failed validation: {error}")
                    .into(),
            )
        })?;
        if current.record_digest != self.expected_current_record_digest {
            return Err(invalid_privacy_parameter(
                "Bootle/Lantern issuer-policy revocation expected a stale or substituted current record",
            ));
        }
        self.successor
            .validate_revocation_successor(&current)
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "Bootle/Lantern issuer-policy revocation rejected: {error}"
                ))
            })?;
        let record = PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(
            self.successor,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?;
        state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
        state_transaction
            .world
            .privacy_commitments
            .insert(key, record);
        Ok(())
    }
}
fn vega_issuer_lineage_revision_count_v1(
    issuer_id: iroha_data_model::privacy::PrivacyIssuerIdV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<usize, Error> {
    let mut count = 0usize;
    for _ in state_transaction
        .world
        .privacy_commitments
        .range(PrivacyCommitmentKeyV1::vega_issuer_lineage_range(issuer_id))
    {
        count = count.checked_add(1).ok_or_else(|| {
            Error::InvariantViolation("Vega issuer lineage count overflow".into())
        })?;
        if count > VEGA_MAX_ISSUER_RECORD_REVISIONS_PER_LINEAGE_V1 {
            return Err(Error::InvariantViolation(
                "persisted Vega issuer lineage exceeds its revision cap".into(),
            ));
        }
    }
    Ok(count)
}
fn validate_vega_issuer_candidate_key_v1(
    record: &PrivacyVegaIssuerRecordV1,
    state_transaction: &StateTransaction<'_, '_>,
) -> Result<PrivacyVegaIssuerRegistryFactsV1, Error> {
    CompressedPointV1::from_slice(record.issuer_public_key.as_bytes()).map_err(|error| {
        invalid_privacy_parameter(format!(
            "Vega issuer revision has an invalid P-256 key: {error}"
        ))
    })?;
    let facts = privacy_vega_issuer_registry_facts_v1(
        record.issuer_public_key,
        &state_transaction.world.privacy_commitments,
    )
    .map_err(|error| {
        Error::InvariantViolation(
            format!("persisted Vega issuer registry is invalid: {error}").into(),
        )
    })?;
    if facts
        .key_owner()
        .is_some_and(|owner| owner != record.issuer_id)
    {
        return Err(invalid_privacy_parameter(
            "Vega issuer public key is permanently owned by another issuer lineage",
        ));
    }
    Ok(facts)
}
impl Execute for RegisterPrivacyVegaIssuerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "Vega issuer registration canonical encoding failed".into(),
                )
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_vega_protocol(state_transaction)?;
        execute_register_privacy_vega_issuer_after_admission_v1(
            self,
            expected_action_index,
            encoded_action_bytes,
            state_transaction,
        )
    }
}
fn execute_register_privacy_vega_issuer_after_admission_v1(
    instruction: RegisterPrivacyVegaIssuerV1,
    expected_action_index: u32,
    encoded_action_bytes: u64,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    instruction.record.validate_initial().map_err(|error| {
        invalid_privacy_parameter(format!("Vega issuer registration rejected: {error}"))
    })?;
    let registry_facts =
        validate_vega_issuer_candidate_key_v1(&instruction.record, state_transaction)?;
    let record_count = registry_facts.record_count();
    if record_count >= VEGA_MAX_ISSUER_RECORDS_V1 {
        return Err(invalid_privacy_parameter(format!(
            "Vega issuer registry is full at {VEGA_MAX_ISSUER_RECORDS_V1} revisions"
        )));
    }
    if vega_issuer_lineage_revision_count_v1(instruction.record.issuer_id, state_transaction)? != 0
    {
        return Err(invalid_privacy_parameter(
            "Vega issuer lineage is already registered",
        ));
    }
    let key = PrivacyCommitmentKeyV1::vega_issuer_revision(
        instruction.record.issuer_id,
        instruction.record.record_epoch,
    )
    .map_err(invalid_privacy_parameter)?;
    let record = PrivacyStateItemRecordV1::vega_issuer_governance(
        instruction.record,
        state_transaction.block_height(),
    )
    .map_err(invalid_privacy_parameter)?;
    state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
    state_transaction
        .world
        .privacy_commitments
        .insert(key, record);
    Ok(())
}
impl Execute for RotatePrivacyVegaIssuerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation("Vega issuer rotation canonical encoding failed".into())
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_vega_protocol(state_transaction)?;
        execute_rotate_privacy_vega_issuer_after_admission_v1(
            self,
            expected_action_index,
            encoded_action_bytes,
            state_transaction,
        )
    }
}
fn execute_rotate_privacy_vega_issuer_after_admission_v1(
    instruction: RotatePrivacyVegaIssuerV1,
    expected_action_index: u32,
    encoded_action_bytes: u64,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if instruction.expected_current_record_digest.is_zero() {
        return Err(invalid_privacy_parameter(
            "Vega expected current issuer-record digest must be non-zero",
        ));
    }
    let registry_facts =
        validate_vega_issuer_candidate_key_v1(&instruction.successor, state_transaction)?;
    let record_count = registry_facts.record_count();
    if record_count >= VEGA_MAX_ISSUER_RECORDS_V1 {
        return Err(invalid_privacy_parameter(format!(
            "Vega issuer registry is full at {VEGA_MAX_ISSUER_RECORDS_V1} revisions"
        )));
    }
    let lineage_count =
        vega_issuer_lineage_revision_count_v1(instruction.successor.issuer_id, state_transaction)?;
    if lineage_count == 0 {
        return Err(invalid_privacy_parameter(
            "Vega issuer lineage is not registered",
        ));
    }
    if lineage_count >= VEGA_MAX_ISSUER_RECORD_REVISIONS_PER_LINEAGE_V1 {
        return Err(invalid_privacy_parameter(format!(
            "Vega issuer lineage is full at {VEGA_MAX_ISSUER_RECORD_REVISIONS_PER_LINEAGE_V1} revisions"
        )));
    }
    let current = load_privacy_vega_issuer_v1(
        instruction.successor.issuer_id,
        &state_transaction.world.privacy_commitments,
    )
    .map_err(|error| {
        Error::InvariantViolation(
            format!("trusted Vega issuer state failed validation: {error}").into(),
        )
    })?;
    if current.record_digest != instruction.expected_current_record_digest {
        return Err(invalid_privacy_parameter(
            "Vega issuer rotation expected a stale or substituted current record",
        ));
    }
    if instruction.successor.issuer_public_key != current.issuer_public_key
        && registry_facts.key_owner() == Some(instruction.successor.issuer_id)
    {
        return Err(invalid_privacy_parameter(
            "Vega issuer rotation cannot reactivate a retired P-256 key",
        ));
    }
    validate_vega_issuer_rotation_v1(&current, &instruction.successor).map_err(|error| {
        invalid_privacy_parameter(format!("Vega issuer rotation rejected: {error}"))
    })?;
    let key = PrivacyCommitmentKeyV1::vega_issuer_revision(
        instruction.successor.issuer_id,
        instruction.successor.record_epoch,
    )
    .map_err(invalid_privacy_parameter)?;
    if state_transaction
        .world
        .privacy_commitments
        .get(&key)
        .is_some()
    {
        return Err(Error::InvariantViolation(
            "Vega issuer successor revision key already exists".into(),
        ));
    }
    let record = PrivacyStateItemRecordV1::vega_issuer_governance(
        instruction.successor,
        state_transaction.block_height(),
    )
    .map_err(invalid_privacy_parameter)?;
    state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
    state_transaction
        .world
        .privacy_commitments
        .insert(key, record);
    Ok(())
}
impl Execute for RevokePrivacyVegaIssuerV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_privacy_governance(authority, state_transaction)?;
        let encoded_action_bytes = norito::canonical_frame_len(&self)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation("Vega issuer revocation canonical encoding failed".into())
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        require_registered_vega_protocol(state_transaction)?;
        execute_revoke_privacy_vega_issuer_after_admission_v1(
            self,
            expected_action_index,
            encoded_action_bytes,
            state_transaction,
        )
    }
}
fn execute_revoke_privacy_vega_issuer_after_admission_v1(
    instruction: RevokePrivacyVegaIssuerV1,
    expected_action_index: u32,
    encoded_action_bytes: u64,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if instruction.expected_current_record_digest.is_zero() {
        return Err(invalid_privacy_parameter(
            "Vega expected current issuer-record digest must be non-zero",
        ));
    }
    let registry_facts =
        validate_vega_issuer_candidate_key_v1(&instruction.successor, state_transaction)?;
    let record_count = registry_facts.record_count();
    if record_count >= VEGA_MAX_ISSUER_RECORDS_V1 {
        return Err(invalid_privacy_parameter(format!(
            "Vega issuer registry is full at {VEGA_MAX_ISSUER_RECORDS_V1} revisions"
        )));
    }
    let lineage_count =
        vega_issuer_lineage_revision_count_v1(instruction.successor.issuer_id, state_transaction)?;
    if lineage_count == 0 {
        return Err(invalid_privacy_parameter(
            "Vega issuer lineage is not registered",
        ));
    }
    if lineage_count >= VEGA_MAX_ISSUER_RECORD_REVISIONS_PER_LINEAGE_V1 {
        return Err(invalid_privacy_parameter(format!(
            "Vega issuer lineage is full at {VEGA_MAX_ISSUER_RECORD_REVISIONS_PER_LINEAGE_V1} revisions"
        )));
    }
    let current = load_privacy_vega_issuer_v1(
        instruction.successor.issuer_id,
        &state_transaction.world.privacy_commitments,
    )
    .map_err(|error| {
        Error::InvariantViolation(
            format!("trusted Vega issuer state failed validation: {error}").into(),
        )
    })?;
    if current.record_digest != instruction.expected_current_record_digest {
        return Err(invalid_privacy_parameter(
            "Vega issuer revocation expected a stale or substituted current record",
        ));
    }
    validate_vega_issuer_revocation_v1(&current, &instruction.successor).map_err(|error| {
        invalid_privacy_parameter(format!("Vega issuer revocation rejected: {error}"))
    })?;
    let key = PrivacyCommitmentKeyV1::vega_issuer_revision(
        instruction.successor.issuer_id,
        instruction.successor.record_epoch,
    )
    .map_err(invalid_privacy_parameter)?;
    if state_transaction
        .world
        .privacy_commitments
        .get(&key)
        .is_some()
    {
        return Err(Error::InvariantViolation(
            "Vega issuer successor revision key already exists".into(),
        ));
    }
    let record = PrivacyStateItemRecordV1::vega_issuer_governance(
        instruction.successor,
        state_transaction.block_height(),
    )
    .map_err(invalid_privacy_parameter)?;
    state_transaction.reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
    state_transaction
        .world
        .privacy_commitments
        .insert(key, record);
    Ok(())
}
fn load_active_bootle_lantern_policy_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    commitments: &impl StorageReadOnly<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
) -> Result<BootleLanternIssuerPolicyV1, Error> {
    let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
        statement.issuer_id,
        statement.policy_id,
    )
    .map_err(invalid_privacy_parameter)?;
    if commitments.get(&key).is_none() {
        return Err(invalid_privacy_parameter(
            "Bootle/Lantern authoritative issuer policy is not registered",
        ));
    }
    let policy = load_privacy_bootle_lantern_issuer_policy_v1(
        statement.issuer_id,
        statement.policy_id,
        commitments,
    )
    .map_err(|error| {
        Error::InvariantViolation(
            format!("trusted Bootle/Lantern issuer-policy state failed validation: {error}").into(),
        )
    })?;
    if policy.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active {
        return Err(invalid_privacy_parameter(
            "Bootle/Lantern authoritative issuer policy is revoked",
        ));
    }
    if (
        &policy.issuer_id,
        &policy.policy_id,
        policy.epoch,
        &policy.record_digest,
        &policy.issuer_parameter_id,
        &policy.issuer_parameter_digest,
    ) != (
        &statement.issuer_id,
        &statement.policy_id,
        statement.issuer_policy_epoch,
        &statement.issuer_policy_record_digest,
        &statement.issuer_parameter_id,
        &statement.issuer_parameter_digest,
    ) {
        return Err(invalid_privacy_parameter(
            "Bootle/Lantern statement does not exactly match authoritative issuer-policy state",
        ));
    }
    Ok(policy)
}
fn load_vega_issuer_for_statement_v1(
    statement: &iroha_data_model::privacy::VegaExistingCredentialStatementV1,
    commitments: &impl StorageReadOnly<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>,
) -> Result<Option<PrivacyVegaIssuerRecordV1>, Error> {
    privacy_vega_issuer_record_count_v1(commitments).map_err(|error| {
        Error::InvariantViolation(
            format!("trusted Vega issuer registry failed validation: {error}").into(),
        )
    })?;
    if commitments
        .range(PrivacyCommitmentKeyV1::vega_issuer_lineage_range(
            statement.issuer_id,
        ))
        .next()
        .is_none()
    {
        return Ok(None);
    }
    load_privacy_vega_issuer_v1(statement.issuer_id, commitments)
        .map(Some)
        .map_err(|error| {
            Error::InvariantViolation(
                format!("trusted Vega issuer state failed validation: {error}").into(),
            )
        })
}
impl Execute for SubmitPrivacyProofV1 {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let submission = PreparedPrivacySubmissionV1::prepare(self, state_transaction)?;
        let activation = *resolve_qualified_privacy_activation_v1(
            state_transaction
                .world
                .privacy_exact12_qualification
                .get()
                .as_ref(),
            &state_transaction.world.privacy_activations,
            submission.envelope.protocol_id,
            state_transaction.block_height(),
        )
        .map_err(invalid_privacy_parameter)?
        .activation();
        submission.execute_after_admission(authority, state_transaction, activation)
    }
}

/// Exact signed submission with its transaction binding consumed and resource limits checked.
///
/// Preparation does not attest production qualification. The public instruction handler must
/// resolve the registered Exact12 qualification before entering native proof/state execution.
struct PreparedPrivacySubmissionV1 {
    envelope: PrivacyProofEnvelopeV1,
    encoded_action_bytes: u64,
    expected_action_index: u32,
}

impl PreparedPrivacySubmissionV1 {
    fn prepare(
        instruction: SubmitPrivacyProofV1,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<Self, Error> {
        let transaction_intent_digest = instruction
            .envelope
            .statement
            .context()
            .transaction_intent_digest;
        let signed_submission_hash =
            crate::privacy::privacy_signed_submission_hash_v1(&instruction).map_err(|error| {
                Error::InvariantViolation(
                    format!("privacy submission canonical encoding failed: {error}").into(),
                )
            })?;
        state_transaction
            .consume_privacy_transaction_intent_v1(
                transaction_intent_digest,
                signed_submission_hash,
            )
            .map_err(|error| {
                invalid_privacy_parameter(format!(
                    "privacy transaction-intent binding rejected: {error}"
                ))
            })?;
        let encoded_action_bytes = norito::canonical_frame_len(&instruction.envelope)
            .ok()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| {
                Error::InvariantViolation("privacy proof envelope canonical encoding failed".into())
            })?;
        let expected_action_index = state_transaction.next_privacy_action_index();
        state_transaction.preflight_privacy_action(expected_action_index, encoded_action_bytes)?;
        Ok(Self {
            envelope: instruction.envelope,
            encoded_action_bytes,
            expected_action_index,
        })
    }

    /// Verify the native proof and stage its complete effects after production admission.
    fn execute_after_admission(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
        activation: PrivacyProtocolActivationRecordV1,
    ) -> Result<(), Error> {
        let expected_action_index = self.expected_action_index;
        let encoded_action_bytes = self.encoded_action_bytes;
        let genesis_hash = state_transaction
            .block_hashes()
            .first()
            .map(|hash| *hash.as_ref())
            .ok_or_else(|| {
                Error::InvariantViolation(
                    "privacy proof admission requires a committed genesis block".into(),
                )
            })?;
        // The single resolver names the one role of this envelope. Trusted-state loading, the
        // verifier dispatch and the effect executor below all follow it; an envelope whose
        // protocol, statement and proof do not name one role is refused before any state is read.
        let role = self.envelope.action_role_v1().map_err(|error| {
            invalid_privacy_parameter(format!(
                "privacy envelope does not select one action role: {error}"
            ))
        })?;
        let pgc_snapshot = if role == PrivacyActionRoleV1::AnonymousPgcPayment {
            let namespace = PrivacyNamespaceV1::from_statement(&self.envelope.statement);
            Some(
                load_privacy_pgc_pool_snapshot_v1(
                    namespace,
                    state_transaction
                        .world
                        .privacy_consensus_policy
                        .get()
                        .current_limits
                        .retained_root_count,
                    &state_transaction.world.privacy_pgc_accounts,
                    &state_transaction.world.privacy_pgc_pool_invariants,
                    &state_transaction.world.privacy_roots,
                    &state_transaction.world.privacy_root_heads,
                )
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("trusted Anonymous PGC pool state failed validation: {error}")
                            .into(),
                    )
                })?,
            )
        } else {
            None
        };
        let orchard_snapshot = if let PrivacyStatementV1::OrchardHalo2ActionsV1(statement) =
            &self.envelope.statement
        {
            let namespace = PrivacyNamespaceV1::from_statement(&self.envelope.statement);
            let snapshot = load_privacy_orchard_pool_snapshot_v1(
                namespace,
                state_transaction
                    .world
                    .privacy_consensus_policy
                    .get()
                    .admission_retained_root_count(),
                &state_transaction.world.privacy_commitments,
                &state_transaction.world.privacy_roots,
                &state_transaction.world.privacy_root_heads,
            )
            .map_err(|error| {
                Error::InvariantViolation(
                    format!("trusted Orchard pool state failed validation: {error}").into(),
                )
            })?;
            if snapshot.state().asset_definition_id() != &statement.asset_definition_id {
                return Err(invalid_privacy_parameter(
                    "Orchard statement asset differs from the governed pool asset",
                ));
            }
            state_transaction
                .world
                .asset_definition(snapshot.state().asset_definition_id())
                .map_err(Error::from)?;
            if state_transaction
                .world
                .accounts
                .get(snapshot.state().reserve_account())
                .is_none()
            {
                return Err(Error::InvariantViolation(
                    "Orchard governed reserve account no longer exists".into(),
                ));
            }
            if authority == snapshot.state().reserve_account()
                && statement.value_balance.direction != PrivacyValueBalanceDirectionV1::Balanced
            {
                return Err(invalid_privacy_parameter(
                    "Orchard reserve account cannot submit a directional public bridge",
                ));
            }
            for action in &statement.actions {
                let nullifier_key =
                    PrivacyNullifierKeyV1::orchard_nullifier(namespace, action.nullifier)
                        .map_err(invalid_privacy_parameter)?;
                if let Some(record) = state_transaction
                    .world
                    .privacy_nullifiers
                    .get(&nullifier_key)
                {
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                            format!("persisted Orchard nullifier provenance is invalid: {error}")
                                .into(),
                        )
                    })?;
                    if !matches!(
                        record,
                        PrivacyStateItemRecordV1::OrchardVerifiedNullifier {
                            bootstrap_digest,
                            ..
                        } if *bootstrap_digest == snapshot.bootstrap_digest()
                    ) {
                        return Err(Error::InvariantViolation(
                            "persisted Orchard nullifier has cross-bootstrap provenance".into(),
                        ));
                    }
                    return Err(invalid_privacy_parameter(
                        "Orchard nullifier was already consumed",
                    ));
                }
            }
            Some(snapshot)
        } else {
            None
        };
        let proof_managed_snapshot = if matches!(
            role,
            PrivacyActionRoleV1::FcmpTransfer
                | PrivacyActionRoleV1::IvmPrivateNoteTransition
                | PrivacyActionRoleV1::PqMaspTransition
        ) {
            let (
                asset_definition_id,
                current_root,
                current_epoch,
                nullifiers,
                output_commitments,
                fcmp_root,
                fcmp_inputs,
                fcmp_outputs,
                program_id,
                value_balance,
                bound_execution_epoch,
            ) = {
                let empty_nullifiers: &[PrivacyNullifierV1] = &[];
                let empty_commitments: &[PrivacyCommitmentV1] = &[];
                match &self.envelope.statement {
                    PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) => (
                        &statement.asset_definition_id,
                        statement.output_set_root.history_commitment(),
                        statement.root_epoch,
                        empty_nullifiers,
                        empty_commitments,
                        Some(statement.output_set_root),
                        Some(statement.inputs.as_slice()),
                        Some(statement.outputs.as_slice()),
                        None,
                        None,
                        None,
                    ),
                    PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) => (
                        &statement.asset_definition_id,
                        statement.state_root,
                        statement.root_epoch,
                        statement.nullifiers.as_slice(),
                        statement.output_commitments.as_slice(),
                        None::<PrivacyFcmpTreeRootV1>,
                        None::<&[PrivacyFcmpInputPublicV1]>,
                        None::<&[PrivacyFcmpOutputTupleV1]>,
                        Some(statement.program_id),
                        Some(statement.value_balance),
                        Some(statement.execution_epoch),
                    ),
                    PrivacyStatementV1::PqMaspStarkV1(statement) => (
                        &statement.asset_definition_id,
                        statement.anchor,
                        statement.anchor_epoch,
                        statement.nullifiers.as_slice(),
                        statement.output_commitments.as_slice(),
                        None::<PrivacyFcmpTreeRootV1>,
                        None::<&[PrivacyFcmpInputPublicV1]>,
                        None::<&[PrivacyFcmpOutputTupleV1]>,
                        None,
                        None,
                        Some(statement.authorization_epoch),
                    ),
                    _ => return Err(role_statement_invariant_v1(role)),
                }
            };
            let namespace = PrivacyNamespaceV1::from_statement(&self.envelope.statement);
            let snapshot = load_privacy_proof_managed_pool_snapshot_v1(
                namespace,
                state_transaction
                    .world
                    .privacy_consensus_policy
                    .get()
                    .admission_retained_root_count(),
                &state_transaction.world.privacy_commitments,
                &state_transaction.world.privacy_roots,
                &state_transaction.world.privacy_root_heads,
            )
            .map_err(|error| {
                Error::InvariantViolation(
                    format!("trusted proof-managed pool state failed validation: {error}").into(),
                )
            })?;
            if snapshot.namespace() != namespace
                || snapshot.bootstrap().asset_definition_id() != asset_definition_id
            {
                return Err(invalid_privacy_parameter(
                    "proof-managed statement differs from its governed pool asset or namespace",
                ));
            }
            state_transaction
                .world
                .asset_definition(asset_definition_id)
                .map_err(Error::from)?;
            if snapshot.retained_current_root()
                != Some((snapshot.current_epoch(), snapshot.current_root()))
            {
                return Err(Error::InvariantViolation(
                    "trusted proof-managed current root is not retained".into(),
                ));
            }
            if !snapshot.contains_retained_root(current_epoch, current_root) {
                return Err(invalid_privacy_parameter(
                    "proof-managed statement anchor is not in the exact retained root window",
                ));
            }
            if let Some(root) = fcmp_root
                && current_epoch == snapshot.current_epoch()
                && current_root == snapshot.current_root()
                && snapshot.fcmp_accumulator_state().map(|state| state.root()) != Some(root)
            {
                return Err(invalid_privacy_parameter(
                    "FCMP++ statement typed root differs from the authoritative curve frontier",
                ));
            }
            if program_id != snapshot.bootstrap().program_id() {
                return Err(invalid_privacy_parameter(
                    "private-IVM statement program differs from its governed pool program",
                ));
            }
            if bound_execution_epoch.is_some_and(|epoch| epoch != current_epoch) {
                return Err(invalid_privacy_parameter(
                    "proof-managed execution/authorization epoch differs from its statement anchor",
                ));
            }
            if let Some(reserve_account) = snapshot.bootstrap().reserve_account() {
                if state_transaction
                    .world
                    .accounts
                    .get(reserve_account)
                    .is_none()
                {
                    return Err(Error::InvariantViolation(
                        "private-IVM governed reserve account no longer exists".into(),
                    ));
                }
                if authority == reserve_account
                    && value_balance.is_some_and(|balance| {
                        balance.direction != PrivacyValueBalanceDirectionV1::Balanced
                    })
                {
                    return Err(invalid_privacy_parameter(
                        "private-IVM reserve account cannot submit a directional public bridge",
                    ));
                }
            } else if value_balance.is_some() {
                return Err(Error::InvariantViolation(
                    "proof-managed value balance has no governed reserve account".into(),
                ));
            }
            let mut seen_nullifier_keys = BTreeSet::new();
            for nullifier in nullifiers {
                let key = PrivacyNullifierKeyV1::proof_managed_nullifier(namespace, *nullifier)
                    .map_err(invalid_privacy_parameter)?;
                if !seen_nullifier_keys.insert(key) {
                    return Err(invalid_privacy_parameter(
                        "proof-managed statement contains duplicate nullifiers",
                    ));
                }
                if let Some(record) = state_transaction.world.privacy_nullifiers.get(&key) {
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                            format!(
                                "persisted proof-managed nullifier provenance is invalid: {error}"
                            )
                            .into(),
                        )
                    })?;
                    if record.proof_managed_pool_bootstrap_digest()
                        != Some(snapshot.bootstrap_digest())
                    {
                        return Err(Error::InvariantViolation(
                            "persisted proof-managed nullifier has cross-bootstrap provenance"
                                .into(),
                        ));
                    }
                    return Err(invalid_privacy_parameter(
                        "proof-managed nullifier was already consumed",
                    ));
                }
            }
            if let Some(inputs) = fcmp_inputs {
                for input in inputs {
                    let key = PrivacyNullifierKeyV1::fcmp_key_image(namespace, input.key_image)
                        .map_err(invalid_privacy_parameter)?;
                    if !seen_nullifier_keys.insert(key) {
                        return Err(invalid_privacy_parameter(
                            "FCMP++ statement contains duplicate key images",
                        ));
                    }
                    if let Some(record) = state_transaction.world.privacy_nullifiers.get(&key) {
                        record.validate().map_err(|error| {
                            Error::InvariantViolation(
                                format!(
                                    "persisted FCMP++ key-image provenance is invalid: {error}"
                                )
                                .into(),
                            )
                        })?;
                        if record.proof_managed_pool_bootstrap_digest()
                            != Some(snapshot.bootstrap_digest())
                        {
                            return Err(Error::InvariantViolation(
                                "persisted FCMP++ key image has cross-bootstrap provenance".into(),
                            ));
                        }
                        return Err(invalid_privacy_parameter(
                            "FCMP++ key image was already consumed",
                        ));
                    }
                }
            }
            let mut seen_commitment_keys = BTreeSet::new();
            for commitment in output_commitments {
                let key =
                    PrivacyCommitmentKeyV1::proof_managed_pool_commitment(namespace, *commitment)
                        .map_err(invalid_privacy_parameter)?;
                if !seen_commitment_keys.insert(key) {
                    return Err(invalid_privacy_parameter(
                        "proof-managed statement contains duplicate output commitments",
                    ));
                }
                if let Some(record) = state_transaction.world.privacy_commitments.get(&key) {
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                            format!(
                                "persisted proof-managed commitment provenance is invalid: {error}"
                            )
                            .into(),
                        )
                    })?;
                    if record.proof_managed_pool_bootstrap_digest()
                        != Some(snapshot.bootstrap_digest())
                    {
                        return Err(Error::InvariantViolation(
                            "persisted proof-managed commitment has cross-bootstrap provenance"
                                .into(),
                        ));
                    }
                    return Err(invalid_privacy_parameter(
                        "proof-managed output commitment already exists",
                    ));
                }
            }
            if let Some(outputs) = fcmp_outputs {
                for output in outputs {
                    let key = PrivacyCommitmentKeyV1::fcmp_output(namespace, output.output_id())
                        .map_err(invalid_privacy_parameter)?;
                    if !seen_commitment_keys.insert(key) {
                        return Err(invalid_privacy_parameter(
                            "FCMP++ statement contains duplicate output ids",
                        ));
                    }
                    if let Some(record) = state_transaction.world.privacy_commitments.get(&key) {
                        record.validate().map_err(|error| {
                            Error::InvariantViolation(
                                format!("persisted FCMP++ output provenance is invalid: {error}")
                                    .into(),
                            )
                        })?;
                        if record.proof_managed_pool_bootstrap_digest()
                            != Some(snapshot.bootstrap_digest())
                        {
                            return Err(Error::InvariantViolation(
                                "persisted FCMP++ output has cross-bootstrap provenance".into(),
                            ));
                        }
                        return Err(invalid_privacy_parameter("FCMP++ output already exists"));
                    }
                }
                snapshot.derive_fcmp_successor(outputs).map_err(|error| {
                    Error::InvariantViolation(
                        format!(
                            "trusted FCMP++ curve frontier could not derive its successor: {error}"
                        )
                        .into(),
                    )
                })?;
            } else {
                snapshot
                    .derive_note_successor(output_commitments)
                    .map_err(|error| {
                        Error::InvariantViolation(
                            format!(
                                "trusted proof-managed frontier could not derive its successor: {error}"
                            )
                            .into(),
                        )
                    })?;
            }
            Some(snapshot)
        } else {
            None
        };
        let zk_ams_snapshot = if let PrivacyStatementV1::IrohaZkAmsV1(statement) =
            &self.envelope.statement
        {
            let namespace = PrivacyNamespaceV1::from_statement(&self.envelope.statement);
            let snapshot = load_privacy_zk_ams_registry_snapshot_v1(
                namespace,
                state_transaction
                    .world
                    .privacy_consensus_policy
                    .get()
                    .admission_retained_root_count(),
                &state_transaction.world.privacy_commitments,
                &state_transaction.world.privacy_roots,
                &state_transaction.world.privacy_root_heads,
            )
            .map_err(|error| {
                Error::InvariantViolation(
                    format!("trusted ZK-AMS registry state failed validation: {error}").into(),
                )
            })?;
            if snapshot.retained_current_root()
                != Some((snapshot.current_epoch(), snapshot.current_root()))
            {
                return Err(Error::InvariantViolation(
                    "trusted ZK-AMS current root is not retained".into(),
                ));
            }
            let expected_issuer_record = zk_ams_issuer_policy_record_digest_v1(
                statement.issuer_id,
                statement.policy_id,
                statement.issuer_public_key,
                statement.policy_digest,
            );
            if statement.issuer_policy_record_digest != expected_issuer_record
                || expected_issuer_record != snapshot.issuer_policy_record_digest()
            {
                return Err(invalid_privacy_parameter(
                    "ZK-AMS statement issuer key/policy does not match governed state",
                ));
            }
            let expected_registry_record = zk_ams_registry_record_digest_v1(
                statement.issuer_id,
                statement.registry_id,
                statement.policy_id,
                expected_issuer_record,
                statement.policy_digest,
                snapshot.current_root(),
                snapshot.current_epoch(),
            );
            if statement.registry_record_digest != expected_registry_record {
                return Err(invalid_privacy_parameter(
                    "ZK-AMS statement registry record does not match the authoritative head",
                ));
            }
            match &statement.action {
                PrivacyZkAmsActionV1::BatchAdmission(batch) => {
                    if batch.account_registry_root != snapshot.current_root()
                        || batch.account_registry_root_epoch != snapshot.current_epoch()
                    {
                        return Err(invalid_privacy_parameter(
                            "ZK-AMS batch admission references a stale or future registry head",
                        ));
                    }
                    let expected_next_epoch =
                        snapshot.current_epoch().checked_add(1).ok_or_else(|| {
                            Error::InvariantViolation("ZK-AMS registry epoch overflow".into())
                        })?;
                    if batch.next_account_registry_root_epoch != expected_next_epoch {
                        return Err(invalid_privacy_parameter(
                            "ZK-AMS batch admission does not advance exactly one epoch",
                        ));
                    }
                    let batch_size = u32::try_from(batch.anchors.len()).map_err(|_| {
                        invalid_privacy_parameter("ZK-AMS batch anchor count cannot be represented")
                    })?;
                    let mut computed_root = snapshot.current_root();
                    for (index, anchor) in batch.anchors.iter().copied().enumerate() {
                        let anchor_index = u32::try_from(index).map_err(|_| {
                            invalid_privacy_parameter(
                                "ZK-AMS batch anchor index cannot be represented",
                            )
                        })?;
                        computed_root = zk_ams_registry_transition_root_v1(
                            statement.registry_id,
                            computed_root,
                            snapshot.current_epoch(),
                            expected_next_epoch,
                            batch_size,
                            anchor_index,
                            anchor,
                        );
                        let phc_key =
                            PrivacyCommitmentKeyV1::zk_ams_phc(namespace, anchor.phc_hash)
                                .map_err(invalid_privacy_parameter)?;
                        if let Some(record) =
                            state_transaction.world.privacy_commitments.get(&phc_key)
                        {
                            record.validate().map_err(|error| {
                                Error::InvariantViolation(
                                    format!("persisted ZK-AMS PHC provenance is invalid: {error}")
                                        .into(),
                                )
                            })?;
                            if !matches!(
                                record,
                                PrivacyStateItemRecordV1::ZkAmsVerifiedProof {
                                    bootstrap_digest,
                                    ..
                                } if *bootstrap_digest == snapshot.bootstrap_digest()
                            ) {
                                return Err(Error::InvariantViolation(
                                    "persisted ZK-AMS PHC has cross-bootstrap provenance".into(),
                                ));
                            }
                            return Err(invalid_privacy_parameter(
                                "ZK-AMS PHC hash was already admitted",
                            ));
                        }
                        let seed_key = PrivacyCommitmentKeyV1::zk_ams_seed_key(
                            namespace,
                            anchor.seed_public_key,
                        )
                        .map_err(invalid_privacy_parameter)?;
                        if let Some(record) =
                            state_transaction.world.privacy_commitments.get(&seed_key)
                        {
                            record.validate().map_err(|error| {
                                Error::InvariantViolation(
                                    format!(
                                        "persisted ZK-AMS seed-key provenance is invalid: {error}"
                                    )
                                    .into(),
                                )
                            })?;
                            if !matches!(
                                record,
                                PrivacyStateItemRecordV1::ZkAmsVerifiedProof {
                                    bootstrap_digest,
                                    ..
                                } if *bootstrap_digest == snapshot.bootstrap_digest()
                            ) {
                                return Err(Error::InvariantViolation(
                                    "persisted ZK-AMS seed key has cross-bootstrap provenance"
                                        .into(),
                                ));
                            }
                            return Err(invalid_privacy_parameter(
                                "ZK-AMS seed key was already admitted",
                            ));
                        }
                    }
                    if computed_root != batch.next_account_registry_root {
                        return Err(invalid_privacy_parameter(
                            "ZK-AMS batch successor root is not the canonical ordered transition",
                        ));
                    }
                }
                PrivacyZkAmsActionV1::ProvisionAccount(provision) => {
                    if provision.account_registry_root != snapshot.current_root()
                        || provision.account_registry_root_epoch != snapshot.current_epoch()
                    {
                        return Err(invalid_privacy_parameter(
                            "ZK-AMS provisioning references a stale or future registry head",
                        ));
                    }
                    for seed_public_key in &provision.admitted_seed_key_ring {
                        let seed_key =
                            PrivacyCommitmentKeyV1::zk_ams_seed_key(namespace, *seed_public_key)
                                .map_err(invalid_privacy_parameter)?;
                        let record = state_transaction
                            .world
                            .privacy_commitments
                            .get(&seed_key)
                            .ok_or_else(|| {
                                invalid_privacy_parameter(
                                    "ZK-AMS provisioning ring contains an unadmitted seed key",
                                )
                            })?;
                        record.validate().map_err(|error| {
                            Error::InvariantViolation(
                                format!("persisted ZK-AMS seed-key provenance is invalid: {error}")
                                    .into(),
                            )
                        })?;
                        if !matches!(
                            record,
                            PrivacyStateItemRecordV1::ZkAmsVerifiedProof {
                                bootstrap_digest,
                                ..
                            } if *bootstrap_digest == snapshot.bootstrap_digest()
                        ) {
                            return Err(Error::InvariantViolation(
                                "persisted ZK-AMS seed key has cross-bootstrap provenance".into(),
                            ));
                        }
                    }
                    let image_key =
                        PrivacyNullifierKeyV1::zk_ams_key_image(namespace, provision.key_image)
                            .map_err(invalid_privacy_parameter)?;
                    if let Some(record) = state_transaction.world.privacy_nullifiers.get(&image_key)
                    {
                        record.validate().map_err(|error| {
                            Error::InvariantViolation(
                                format!(
                                    "persisted ZK-AMS key-image provenance is invalid: {error}"
                                )
                                .into(),
                            )
                        })?;
                        if !matches!(
                            record,
                            PrivacyStateItemRecordV1::ZkAmsVerifiedProof {
                                bootstrap_digest,
                                ..
                            } if *bootstrap_digest == snapshot.bootstrap_digest()
                        ) {
                            return Err(Error::InvariantViolation(
                                "persisted ZK-AMS key image has cross-bootstrap provenance".into(),
                            ));
                        }
                        return Err(invalid_privacy_parameter(
                            "ZK-AMS provisioning key image was already consumed",
                        ));
                    }
                    if state_transaction
                        .world
                        .accounts
                        .get(&provision.account_id)
                        .is_some()
                    {
                        return Err(invalid_privacy_parameter(
                            "ZK-AMS provisioning target account already exists",
                        ));
                    }
                }
            }
            Some(snapshot)
        } else {
            None
        };
        let (zk_x509_snapshot, zk_x509_nullifier_key, zk_x509_nullifier_consumed) =
            if let PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) = &self.envelope.statement
            {
                if authority != &statement.wallet_account {
                    return Err(invalid_privacy_parameter(
                        "X.509 certificate proof must be submitted by its bound wallet account",
                    ));
                }
                if state_transaction
                    .world
                    .accounts
                    .get(&statement.wallet_account)
                    .is_none()
                {
                    return Err(invalid_privacy_parameter(
                        "X.509 statement wallet account does not exist",
                    ));
                }
                let snapshot = load_privacy_zk_x509_authoritative_state_v1(
                    statement.trust_anchor_id,
                    statement.certificate_policy_id,
                    state_transaction
                        .world
                        .privacy_consensus_policy
                        .get()
                        .admission_retained_root_count(),
                    &state_transaction.world.privacy_commitments,
                    &state_transaction.world.privacy_roots,
                    &state_transaction.world.privacy_root_heads,
                )
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("trusted X.509 authoritative state failed validation: {error}")
                            .into(),
                    )
                })?;
                let nullifier_key = PrivacyNullifierKeyV1::zk_x509_certificate_nullifier(
                    snapshot.namespace(),
                    statement.certificate_nullifier,
                )
                .map_err(invalid_privacy_parameter)?;
                let consumed = if let Some(record) = state_transaction
                    .world
                    .privacy_nullifiers
                    .get(&nullifier_key)
                {
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                        format!(
                            "persisted X.509 certificate-nullifier provenance is invalid: {error}"
                        )
                        .into(),
                    )
                    })?;
                    if !matches!(
                        record,
                        PrivacyStateItemRecordV1::ZkX509VerifiedCertificateNullifier { .. }
                    ) {
                        return Err(Error::InvariantViolation(
                            "persisted X.509 certificate nullifier has wrong-role provenance"
                                .into(),
                        ));
                    }
                    true
                } else {
                    false
                };
                (Some(snapshot), Some(nullifier_key), consumed)
            } else {
                (None, None, false)
            };
        let bootle_lantern_policy =
            if let PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement) =
                &self.envelope.statement
            {
                Some(load_active_bootle_lantern_policy_v1(
                    statement,
                    &state_transaction.world.privacy_commitments,
                )?)
            } else {
                None
            };
        let vega_issuer_record = if let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) =
            &self.envelope.statement
        {
            load_vega_issuer_for_statement_v1(
                statement,
                &state_transaction.world.privacy_commitments,
            )?
        } else {
            None
        };
        let (zk_ace_policy, zk_ace_replay_key) =
            if let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) = &self.envelope.statement
            {
                let policy_key = PrivacyCommitmentKeyV1::zk_ace_policy(statement.policy_id)
                    .map_err(invalid_privacy_parameter)?;
                if state_transaction
                    .world
                    .privacy_commitments
                    .get(&policy_key)
                    .is_none()
                {
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE authoritative policy is not registered",
                    ));
                }
                let policy = load_privacy_zk_ace_policy_v1(
                    statement.policy_id,
                    &state_transaction.world.privacy_commitments,
                )
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("trusted ZK-ACE policy state failed validation: {error}").into(),
                    )
                })?;
                if policy.lifecycle != PrivacyZkAcePolicyLifecycleV1::Active {
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE authoritative policy is revoked",
                    ));
                }
                if policy.policy_id != statement.policy_id
                    || policy.policy_digest != statement.policy_digest
                    || policy.identity_commitment != statement.identity_commitment
                    || policy.authorization_epoch != statement.authorization_epoch
                    || policy.asset_definition_id != statement.asset_definition_id
                {
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE statement does not exactly match authoritative policy state",
                    ));
                }
                if policy
                    .source_allowlist
                    .binary_search(&statement.source)
                    .is_err()
                {
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE source account is not authorized by policy",
                    ));
                }
                if state_transaction
                    .world
                    .accounts
                    .get(&statement.source)
                    .is_none()
                {
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE source account does not exist",
                    ));
                }
                if state_transaction
                    .world
                    .accounts
                    .get(&statement.destination)
                    .is_none()
                {
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE destination account does not exist",
                    ));
                }
                state_transaction
                    .world
                    .asset_definition(&statement.asset_definition_id)
                    .map_err(Error::from)?;
                let replay_key = PrivacyNullifierKeyV1::zk_ace_replay(
                    statement.policy_id,
                    statement.replay_nullifier,
                )
                .map_err(invalid_privacy_parameter)?;
                if let Some(record) = state_transaction.world.privacy_nullifiers.get(&replay_key) {
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                            format!("persisted ZK-ACE replay provenance is invalid: {error}")
                                .into(),
                        )
                    })?;
                    if !matches!(
                        record,
                        PrivacyStateItemRecordV1::ZkAceVerifiedAuthorization {
                            policy_id,
                            ..
                        } if *policy_id == statement.policy_id
                    ) {
                        return Err(Error::InvariantViolation(
                            "persisted ZK-ACE replay marker has wrong-policy provenance".into(),
                        ));
                    }
                    return Err(invalid_privacy_parameter(
                        "ZK-ACE replay nullifier was already consumed",
                    ));
                }
                (Some(policy), Some(replay_key))
            } else {
                (None, None)
            };
        match &self.envelope.statement {
            PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) => {
                super::asset::isi::validate_committed_public_balance_scope(
                    state_transaction,
                    &statement.asset_definition_id,
                    statement.public_balance_scope,
                    "ZK-ACE authorization",
                )?;
            }
            PrivacyStatementV1::OrchardHalo2ActionsV1(statement) => {
                super::asset::isi::validate_committed_public_balance_scope(
                    state_transaction,
                    &statement.asset_definition_id,
                    statement.public_balance_scope,
                    "Orchard action",
                )?;
            }
            PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) => {
                super::asset::isi::validate_committed_public_balance_scope(
                    state_transaction,
                    &statement.asset_definition_id,
                    statement.public_balance_scope,
                    "private-IVM action",
                )?;
            }
            _ => {}
        }
        let pgc_verification_state =
            pgc_snapshot
                .as_ref()
                .map(|snapshot| PrivacyPgcVerificationStateV1 {
                    namespace: snapshot.namespace(),
                    total_supply: snapshot.invariant().total_supply(),
                    bootstrap_digest: snapshot.invariant().bootstrap_digest(),
                    bootstrap_proof_digest: snapshot.invariant().bootstrap_proof_digest(),
                    current_root: snapshot.current_root(),
                    current_epoch: snapshot.current_epoch(),
                    retained_current_root: snapshot.retained_current_root(),
                    accounts: snapshot.accounts(),
                });
        let effects = verify_privacy_envelope_v1(
            &self.envelope,
            PrivacyVerificationContextV1 {
                activation: &activation,
                consensus_limits: &state_transaction
                    .world
                    .privacy_consensus_policy
                    .get()
                    .current_limits,
                network_id: &state_transaction.network_id,
                genesis_hash,
                current_height: state_transaction.block_height(),
                expected_action_index,
                block_timestamp_ms: state_transaction.block_unix_timestamp_ms(),
                pgc_state: pgc_verification_state,
                orchard_state: orchard_snapshot.as_ref(),
                proof_managed_state: proof_managed_snapshot.as_ref(),
                zk_x509_state: zk_x509_snapshot.as_ref().map(|authoritative_state| {
                    PrivacyZkX509VerificationStateV1 {
                        authoritative_state,
                        certificate_nullifier_consumed: zk_x509_nullifier_consumed,
                    }
                }),
                bootle_lantern_policy: bootle_lantern_policy.as_ref(),
                vega_issuer_record: vega_issuer_record.as_ref(),
            },
        )
        .map_err(privacy_verification_error)?;
        if effects.role() != role
            || effects.protocol_id() != self.envelope.protocol_id
            || effects.statement_digest() != self.envelope.statement_digest
            || effects.action_index() != expected_action_index
            || effects.encoded_action_bytes() != encoded_action_bytes
        {
            return Err(Error::InvariantViolation(
                "native privacy verifier returned effects inconsistent with its envelope".into(),
            ));
        }
        match effects.into_ledger() {
            VerifiedPrivacyLedgerEffectsV1::None => state_transaction
                .reserve_privacy_action(expected_action_index, encoded_action_bytes),
            VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(effect) => {
                let snapshot = zk_x509_snapshot.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native X.509 effect has no trusted authoritative snapshot".into(),
                    )
                })?;
                let PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) =
                    &self.envelope.statement
                else {
                    return Err(Error::InvariantViolation(
                        "native X.509 effect has a different statement type".into(),
                    ));
                };
                let trust_anchor = snapshot.trust_anchor();
                let certificate_policy = snapshot.certificate_policy();
                let crl = snapshot.crl_record();
                if effect.namespace != snapshot.namespace()
                    || effect.certificate_nullifier != statement.certificate_nullifier
                    || effect.trust_anchor_record_digest != trust_anchor.record_digest
                    || effect.trust_anchor_record_epoch != trust_anchor.record_epoch
                    || effect.certificate_policy_record_digest != certificate_policy.record_digest
                    || effect.certificate_policy_record_epoch != certificate_policy.record_epoch
                    || effect.crl_record_digest != crl.record_digest
                    || effect.crl_record_epoch != crl.record_epoch
                {
                    return Err(Error::InvariantViolation(
                        "native X.509 effect is inconsistent with trusted state or its statement"
                            .into(),
                    ));
                }
                let nullifier_key = PrivacyNullifierKeyV1::zk_x509_certificate_nullifier(
                    effect.namespace,
                    effect.certificate_nullifier,
                )
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("verified X.509 certificate nullifier is invalid: {error}").into(),
                    )
                })?;
                if zk_x509_nullifier_key != Some(nullifier_key) {
                    return Err(Error::InvariantViolation(
                        "native X.509 effect selected a different replay key".into(),
                    ));
                }
                if let Some(record) = state_transaction
                    .world
                    .privacy_nullifiers
                    .get(&nullifier_key)
                {
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                            format!(
                                "persisted X.509 certificate-nullifier provenance is invalid: {error}"
                            )
                            .into(),
                        )
                    })?;
                    if !matches!(
                        record,
                        PrivacyStateItemRecordV1::ZkX509VerifiedCertificateNullifier { .. }
                    ) {
                        return Err(Error::InvariantViolation(
                            "persisted X.509 certificate nullifier has wrong-role provenance"
                                .into(),
                        ));
                    }
                    return Err(invalid_privacy_parameter(
                        "X.509 certificate nullifier was already consumed",
                    ));
                }
                let provenance = PrivacyStateItemRecordV1::zk_x509_verified_certificate_nullifier(
                    effect.trust_anchor_record_digest,
                    effect.trust_anchor_record_epoch,
                    effect.certificate_policy_record_digest,
                    effect.certificate_policy_record_epoch,
                    effect.crl_record_digest,
                    effect.crl_record_epoch,
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                )
                .map_err(invalid_privacy_parameter)?;
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                state_transaction
                    .world
                    .privacy_nullifiers
                    .insert(nullifier_key, provenance);
                Ok(())
            }
            VerifiedPrivacyLedgerEffectsV1::OrchardActions(effect) => {
                let snapshot = orchard_snapshot.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native Orchard effect has no trusted pool snapshot".into(),
                    )
                })?;
                let PrivacyStatementV1::OrchardHalo2ActionsV1(statement) = &self.envelope.statement
                else {
                    return Err(Error::InvariantViolation(
                        "native Orchard effect has a different statement type".into(),
                    ));
                };
                let note_commitments = statement
                    .actions
                    .iter()
                    .map(|action| action.note_commitment)
                    .collect::<Vec<_>>();
                let expected_successor =
                    snapshot
                        .derive_successor(&note_commitments)
                        .map_err(|error| {
                            Error::InvariantViolation(
                            format!(
                                "trusted Orchard frontier could not derive its successor: {error}"
                            )
                            .into(),
                        )
                        })?;
                if effect.namespace() != snapshot.namespace()
                    || effect.bootstrap_digest() != snapshot.bootstrap_digest()
                    || effect.asset_definition_id() != snapshot.state().asset_definition_id()
                    || effect.asset_definition_id() != &statement.asset_definition_id
                    || effect.public_balance_scope() != snapshot.state().public_balance_scope()
                    || effect.public_balance_scope() != statement.public_balance_scope
                    || effect.reserve_account() != snapshot.state().reserve_account()
                    || effect.anchor() != statement.anchor
                    || effect.anchor_epoch() != statement.anchor_epoch
                    || !snapshot.contains_retained_anchor(effect.anchor_epoch(), effect.anchor())
                    || effect.current_root() != snapshot.current_root()
                    || effect.current_epoch() != snapshot.current_epoch()
                    || effect.successor_state() != &expected_successor
                    || effect.nullifiers().len() != statement.actions.len()
                    || effect
                        .nullifiers()
                        .iter()
                        .zip(&statement.actions)
                        .any(|(nullifier, action)| *nullifier != action.nullifier)
                    || effect.value_balance() != statement.value_balance
                    || effect.expiry_height() != statement.expiry_height
                    || state_transaction.block_height() > effect.expiry_height()
                {
                    return Err(Error::InvariantViolation(
                        "native Orchard effect is inconsistent with trusted state or its statement"
                            .into(),
                    ));
                }
                if authority == effect.reserve_account()
                    && effect.value_balance().direction != PrivacyValueBalanceDirectionV1::Balanced
                {
                    return Err(invalid_privacy_parameter(
                        "Orchard reserve account cannot submit a directional public bridge",
                    ));
                }
                let mut seen_nullifiers = BTreeSet::new();
                let mut nullifier_keys = Vec::with_capacity(effect.nullifiers().len());
                for nullifier in effect.nullifiers() {
                    let key =
                        PrivacyNullifierKeyV1::orchard_nullifier(effect.namespace(), *nullifier)
                            .map_err(|error| {
                                Error::InvariantViolation(
                                    format!("verified Orchard nullifier is invalid: {error}")
                                        .into(),
                                )
                            })?;
                    if !seen_nullifiers.insert(key) {
                        return Err(Error::InvariantViolation(
                            "native Orchard effect contains duplicate nullifier keys".into(),
                        ));
                    }
                    if state_transaction
                        .world
                        .privacy_nullifiers
                        .get(&key)
                        .is_some()
                    {
                        return Err(invalid_privacy_parameter(
                            "verified Orchard nullifier was already consumed",
                        ));
                    }
                    nullifier_keys.push(key);
                }
                let nullifier_record = PrivacyStateItemRecordV1::orchard_verified_nullifier(
                    effect.bootstrap_digest(),
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                )
                .map_err(invalid_privacy_parameter)?;
                let state_key = PrivacyCommitmentKeyV1::orchard_pool_state(effect.namespace())
                    .map_err(invalid_privacy_parameter)?;
                let state_record =
                    PrivacyStateItemRecordV1::orchard_pool_state(effect.successor_state().clone())
                        .map_err(invalid_privacy_parameter)?;
                let root_provenance = PrivacyRootProvenanceV1::orchard_pool_successor(
                    effect.bootstrap_digest(),
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                    snapshot.current_epoch(),
                    snapshot.current_root(),
                )
                .map_err(invalid_privacy_parameter)?;
                let root_key = PrivacyRootKeyV1::new(
                    effect.namespace(),
                    PrivacyRootRoleV1::NoteCommitmentAnchor,
                    effect.successor_state().epoch(),
                    effect.successor_state().root(),
                )
                .map_err(invalid_privacy_parameter)?;
                let head_key = PrivacyRootHeadKeyV1::new(
                    effect.namespace(),
                    PrivacyRootRoleV1::NoteCommitmentAnchor,
                )
                .map_err(invalid_privacy_parameter)?;
                let removals = plan_privacy_root_history_update_v1(
                    &state_transaction.world.privacy_roots,
                    &[root_key],
                    state_transaction
                        .world
                        .privacy_consensus_policy
                        .get()
                        .admission_retained_root_count(),
                )
                .map_err(|error| {
                    invalid_privacy_parameter(format!("Orchard successor root rejected: {error}"))
                })?;
                let retention_anchor = removals
                    .last()
                    .map(|key| PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root()))
                    .transpose()
                    .map_err(invalid_privacy_parameter)?
                    .or_else(|| snapshot.retention_anchor());
                let root_head = PrivacyRootHeadRecordV1::new(
                    effect.successor_state().epoch(),
                    effect.successor_state().root(),
                    root_provenance,
                    retention_anchor,
                )
                .map_err(invalid_privacy_parameter)?;
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                let balance = effect.value_balance();
                if balance.direction != PrivacyValueBalanceDirectionV1::Balanced {
                    super::asset::isi::execute_verified_privacy_pool_public_balance_transfer(
                        state_transaction,
                        authority,
                        self.envelope.statement_digest,
                        PrivacyPublicReserveOwnerV1::Orchard {
                            namespace: snapshot.namespace(),
                            bootstrap_digest: snapshot.bootstrap_digest(),
                        },
                        effect.asset_definition_id(),
                        effect.public_balance_scope(),
                        effect.reserve_account(),
                        balance.direction,
                        Quantity::from(balance.amount),
                    )?;
                }
                for key in removals {
                    state_transaction.world.privacy_roots.remove(key);
                }
                for key in nullifier_keys {
                    state_transaction
                        .world
                        .privacy_nullifiers
                        .insert(key, nullifier_record.clone());
                }
                state_transaction
                    .world
                    .privacy_commitments
                    .insert(state_key, state_record);
                state_transaction
                    .world
                    .privacy_roots
                    .insert(root_key, root_provenance);
                state_transaction
                    .world
                    .privacy_root_heads
                    .insert(head_key, root_head);
                Ok(())
            }
            VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(effect) => {
                let snapshot = proof_managed_snapshot.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native proof-managed effect has no trusted pool snapshot".into(),
                    )
                })?;
                let (
                    asset_definition_id,
                    statement_anchor_is_valid,
                    value_balance,
                    public_balance_scope,
                ) = match &self.envelope.statement {
                    PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) => (
                        &statement.asset_definition_id,
                        snapshot.contains_retained_root(
                            statement.root_epoch,
                            statement.output_set_root.history_commitment(),
                        ),
                        None,
                        None,
                    ),
                    PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) => (
                        &statement.asset_definition_id,
                        snapshot.contains_retained_root(statement.root_epoch, statement.state_root),
                        Some(statement.value_balance),
                        Some(statement.public_balance_scope),
                    ),
                    PrivacyStatementV1::PqMaspStarkV1(statement) => (
                        &statement.asset_definition_id,
                        snapshot.contains_retained_root(statement.anchor_epoch, statement.anchor),
                        None,
                        None,
                    ),
                    _ => {
                        return Err(Error::InvariantViolation(
                            "native proof-managed effect has a different statement type".into(),
                        ));
                    }
                };
                if effect.namespace() != snapshot.namespace()
                    || effect.bootstrap_digest() != snapshot.bootstrap_digest()
                    || effect.asset_definition_id() != asset_definition_id
                    || effect.asset_definition_id() != snapshot.bootstrap().asset_definition_id()
                    || !statement_anchor_is_valid
                    || effect.current_root() != snapshot.current_root()
                    || effect.current_epoch() != snapshot.current_epoch()
                    || effect.next_epoch()
                        != effect.current_epoch().checked_add(1).ok_or_else(|| {
                            Error::InvariantViolation("proof-managed pool epoch overflow".into())
                        })?
                    || effect.next_root() == effect.current_root()
                    || effect.value_balance() != value_balance
                    || effect.public_balance_scope() != public_balance_scope
                    || effect.public_balance_scope() != snapshot.bootstrap().public_balance_scope()
                {
                    return Err(Error::InvariantViolation(
                        "native proof-managed effect is inconsistent with trusted state or its statement"
                            .into(),
                    ));
                }
                let reserve_account = snapshot.bootstrap().reserve_account();
                match (effect.value_balance(), reserve_account) {
                    (Some(balance), Some(reserve_account)) => {
                        if authority == reserve_account
                            && balance.direction != PrivacyValueBalanceDirectionV1::Balanced
                        {
                            return Err(invalid_privacy_parameter(
                                "proof-managed reserve account cannot submit a directional public bridge",
                            ));
                        }
                    }
                    (None, None) => {}
                    _ => {
                        return Err(Error::InvariantViolation(
                            "native proof-managed public balance differs from governed reserve state"
                                .into(),
                        ));
                    }
                }
                let (nullifier_len, output_len) = match effect.transition() {
                    VerifiedProofManagedPoolTransitionV1::Fcmp {
                        key_images,
                        outputs,
                        ..
                    } => (key_images.len(), outputs.len()),
                    VerifiedProofManagedPoolTransitionV1::IvmPrivateNote {
                        nullifiers,
                        output_commitments,
                        ..
                    }
                    | VerifiedProofManagedPoolTransitionV1::PqMasp {
                        nullifiers,
                        output_commitments,
                        ..
                    } => (nullifiers.len(), output_commitments.len()),
                };
                let nullifier_count = u32::try_from(nullifier_len).map_err(|_| {
                    Error::InvariantViolation(
                        "proof-managed verified nullifier count overflow".into(),
                    )
                })?;
                let output_count = u32::try_from(output_len).map_err(|_| {
                    Error::InvariantViolation("proof-managed verified output count overflow".into())
                })?;
                let verified_nullifier =
                    PrivacyStateItemRecordV1::proof_managed_pool_verified_nullifier(
                        effect.bootstrap_digest(),
                        self.envelope.statement_digest,
                        nullifier_count,
                        output_count,
                        state_transaction.block_height(),
                        expected_action_index,
                    )
                    .map_err(invalid_privacy_parameter)?;
                let (nullifier_keys, output_records, accumulator_state) = match effect.transition()
                {
                    VerifiedProofManagedPoolTransitionV1::Fcmp {
                        key_images,
                        outputs,
                        successor_state,
                    } => {
                        let mut seen_nullifier_keys = BTreeSet::new();
                        let mut nullifier_keys = Vec::new();
                        let mut seen_commitment_keys = BTreeSet::new();
                        let mut output_records = Vec::new();
                        let PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) =
                            &self.envelope.statement
                        else {
                            return Err(Error::InvariantViolation(
                                "native FCMP++ effect has a different statement type".into(),
                            ));
                        };
                        let expected_key_images = statement
                            .inputs
                            .iter()
                            .map(|input| input.key_image)
                            .collect::<Vec<_>>();
                        let expected_successor = snapshot
                            .derive_fcmp_successor(&statement.outputs)
                            .map_err(|error| {
                                Error::InvariantViolation(
                                    format!(
                                        "trusted FCMP++ curve frontier could not derive its successor: {error}"
                                    )
                                    .into(),
                                )
                            })?;
                        if key_images != &expected_key_images
                            || outputs != &statement.outputs
                            || successor_state != &expected_successor
                            || effect.next_epoch() != expected_successor.epoch()
                            || effect.next_root() != expected_successor.root().history_commitment()
                        {
                            return Err(Error::InvariantViolation(
                                "native FCMP++ effect differs from its statement or validator-derived successor"
                                    .into(),
                            ));
                        }
                        nullifier_keys
                            .try_reserve_exact(key_images.len())
                            .map_err(|_| {
                                Error::InvariantViolation(
                                    "verified FCMP++ key-image allocation failed".into(),
                                )
                            })?;
                        for key_image in key_images {
                            let key = PrivacyNullifierKeyV1::fcmp_key_image(
                                effect.namespace(),
                                *key_image,
                            )
                            .map_err(|error| {
                                Error::InvariantViolation(
                                    format!("verified FCMP++ key image is invalid: {error}").into(),
                                )
                            })?;
                            if !seen_nullifier_keys.insert(key)
                                || state_transaction
                                    .world
                                    .privacy_nullifiers
                                    .get(&key)
                                    .is_some()
                            {
                                return Err(invalid_privacy_parameter(
                                    "verified FCMP++ key image is duplicate or already consumed",
                                ));
                            }
                            nullifier_keys.push(key);
                        }
                        output_records
                            .try_reserve_exact(outputs.len())
                            .map_err(|_| {
                                Error::InvariantViolation(
                                    "verified FCMP++ output allocation failed".into(),
                                )
                            })?;
                        for (output_index, output) in outputs.iter().copied().enumerate() {
                            let key = PrivacyCommitmentKeyV1::fcmp_output(
                                effect.namespace(),
                                output.output_id(),
                            )
                            .map_err(|error| {
                                Error::InvariantViolation(
                                    format!("verified FCMP++ output is invalid: {error}").into(),
                                )
                            })?;
                            if !seen_commitment_keys.insert(key)
                                || state_transaction
                                    .world
                                    .privacy_commitments
                                    .get(&key)
                                    .is_some()
                            {
                                return Err(invalid_privacy_parameter(
                                    "verified FCMP++ output is duplicate or already exists",
                                ));
                            }
                            let output_index = u32::try_from(output_index).map_err(|_| {
                                Error::InvariantViolation(
                                    "verified FCMP++ output index overflow".into(),
                                )
                            })?;
                            let append_position = snapshot
                                .output_count()
                                .checked_add(u64::from(output_index))
                                .ok_or_else(|| {
                                    Error::InvariantViolation(
                                        "verified FCMP++ append position overflow".into(),
                                    )
                                })?;
                            let record = PrivacyStateItemRecordV1::fcmp_verified_output(
                                effect.bootstrap_digest(),
                                output,
                                self.envelope.statement_digest,
                                effect.next_epoch(),
                                output_index,
                                append_position,
                                nullifier_count,
                                output_count,
                                state_transaction.block_height(),
                                expected_action_index,
                            )
                            .map_err(invalid_privacy_parameter)?;
                            output_records.push((key, record));
                        }
                        (
                            nullifier_keys,
                            output_records,
                            PrivacyProofManagedPoolAccumulatorStateV1::Fcmp(expected_successor),
                        )
                    }
                    VerifiedProofManagedPoolTransitionV1::IvmPrivateNote {
                        nullifiers,
                        output_commitments,
                        successor_state,
                    } => {
                        let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) =
                            &self.envelope.statement
                        else {
                            return Err(Error::InvariantViolation(
                                "native private-IVM effect has a different statement type".into(),
                            ));
                        };
                        prepare_proof_managed_note_apply_v1(
                            ProofManagedNoteApplyContextV1 {
                                effect: &effect,
                                snapshot,
                                statement_digest: self.envelope.statement_digest,
                                block_height: state_transaction.block_height(),
                                expected_action_index,
                                state_transaction,
                            },
                            TypedProofManagedNoteApplyV1::IvmPrivateNote {
                                statement,
                                nullifiers,
                                output_commitments,
                                successor_state,
                            },
                        )?
                    }
                    VerifiedProofManagedPoolTransitionV1::PqMasp {
                        nullifiers,
                        output_commitments,
                        successor_state,
                    } => {
                        let PrivacyStatementV1::PqMaspStarkV1(statement) = &self.envelope.statement
                        else {
                            return Err(Error::InvariantViolation(
                                "native PQ-MASP effect has a different statement type".into(),
                            ));
                        };
                        prepare_proof_managed_note_apply_v1(
                            ProofManagedNoteApplyContextV1 {
                                effect: &effect,
                                snapshot,
                                statement_digest: self.envelope.statement_digest,
                                block_height: state_transaction.block_height(),
                                expected_action_index,
                                state_transaction,
                            },
                            TypedProofManagedNoteApplyV1::PqMasp {
                                statement,
                                nullifiers,
                                output_commitments,
                                successor_state,
                            },
                        )?
                    }
                };
                let config_key =
                    PrivacyCommitmentKeyV1::proof_managed_pool_config(effect.namespace())
                        .map_err(invalid_privacy_parameter)?;
                let config_record = PrivacyStateItemRecordV1::proof_managed_pool_state(
                    snapshot.bootstrap().clone(),
                    snapshot.bootstrap_digest(),
                    snapshot.initial_root(),
                    accumulator_state,
                    snapshot.bootstrap_admitted_at_height(),
                )
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("verified proof-managed successor state is invalid: {error}")
                            .into(),
                    )
                })?;
                let root_provenance = PrivacyRootProvenanceV1::proof_managed_pool_successor(
                    effect.bootstrap_digest(),
                    self.envelope.protocol_id,
                    self.envelope.statement_digest,
                    nullifier_count,
                    output_count,
                    state_transaction.block_height(),
                    expected_action_index,
                    snapshot.current_epoch(),
                    snapshot.current_root(),
                )
                .map_err(invalid_privacy_parameter)?;
                let root_key = PrivacyRootKeyV1::new(
                    effect.namespace(),
                    snapshot.root_role(),
                    effect.next_epoch(),
                    effect.next_root(),
                )
                .map_err(invalid_privacy_parameter)?;
                let head_key = PrivacyRootHeadKeyV1::new(effect.namespace(), snapshot.root_role())
                    .map_err(invalid_privacy_parameter)?;
                let removals = plan_privacy_root_history_update_v1(
                    &state_transaction.world.privacy_roots,
                    &[root_key],
                    state_transaction
                        .world
                        .privacy_consensus_policy
                        .get()
                        .admission_retained_root_count(),
                )
                .map_err(|error| {
                    invalid_privacy_parameter(format!(
                        "proof-managed successor root rejected: {error}"
                    ))
                })?;
                let retention_anchor = removals
                    .last()
                    .map(|key| PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root()))
                    .transpose()
                    .map_err(invalid_privacy_parameter)?
                    .or_else(|| snapshot.retention_anchor());
                let root_head = PrivacyRootHeadRecordV1::new(
                    effect.next_epoch(),
                    effect.next_root(),
                    root_provenance,
                    retention_anchor,
                )
                .map_err(invalid_privacy_parameter)?;
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                if let (Some(balance), Some(reserve_account)) =
                    (effect.value_balance(), reserve_account)
                    && balance.direction != PrivacyValueBalanceDirectionV1::Balanced
                {
                    let public_balance_scope = effect.public_balance_scope().ok_or_else(|| {
                        Error::InvariantViolation(
                            "directional proof-managed bridge has no committed public balance scope"
                                .into(),
                        )
                    })?;
                    super::asset::isi::execute_verified_privacy_pool_public_balance_transfer(
                        state_transaction,
                        authority,
                        self.envelope.statement_digest,
                        PrivacyPublicReserveOwnerV1::PrivateIvm {
                            namespace: snapshot.namespace(),
                            bootstrap_digest: snapshot.bootstrap_digest(),
                        },
                        effect.asset_definition_id(),
                        public_balance_scope,
                        reserve_account,
                        balance.direction,
                        Quantity::from(balance.amount),
                    )?;
                }
                for key in removals {
                    state_transaction.world.privacy_roots.remove(key);
                }
                for key in nullifier_keys {
                    state_transaction
                        .world
                        .privacy_nullifiers
                        .insert(key, verified_nullifier.clone());
                }
                for (key, record) in output_records {
                    state_transaction
                        .world
                        .privacy_commitments
                        .insert(key, record);
                }
                state_transaction
                    .world
                    .privacy_commitments
                    .insert(config_key, config_record);
                state_transaction
                    .world
                    .privacy_roots
                    .insert(root_key, root_provenance);
                state_transaction
                    .world
                    .privacy_root_heads
                    .insert(head_key, root_head);
                Ok(())
            }
            VerifiedPrivacyLedgerEffectsV1::ZkAceAuthorization(effect) => {
                let policy = zk_ace_policy.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native ZK-ACE effect has no trusted policy state".into(),
                    )
                })?;
                let replay_key = zk_ace_replay_key.ok_or_else(|| {
                    Error::InvariantViolation(
                        "native ZK-ACE effect has no trusted replay key".into(),
                    )
                })?;
                let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) =
                    &self.envelope.statement
                else {
                    return Err(Error::InvariantViolation(
                        "native ZK-ACE effect has a different statement type".into(),
                    ));
                };
                if effect.policy_id != statement.policy_id
                    || effect.policy_digest != statement.policy_digest
                    || effect.identity_commitment != statement.identity_commitment
                    || effect.authorization_epoch != statement.authorization_epoch
                    || effect.source != statement.source
                    || effect.destination != statement.destination
                    || effect.asset_definition_id != statement.asset_definition_id
                    || effect.public_balance_scope != statement.public_balance_scope
                    || effect.amount != statement.amount
                    || effect.replay_nullifier != statement.replay_nullifier
                    || effect.policy_id != policy.policy_id
                    || effect.policy_digest != policy.policy_digest
                    || effect.identity_commitment != policy.identity_commitment
                    || effect.authorization_epoch != policy.authorization_epoch
                    || effect.asset_definition_id != policy.asset_definition_id
                    || policy
                        .source_allowlist
                        .binary_search(&effect.source)
                        .is_err()
                {
                    return Err(Error::InvariantViolation(
                        "native ZK-ACE effect is inconsistent with trusted state or its statement"
                            .into(),
                    ));
                }
                let expected_replay_key =
                    PrivacyNullifierKeyV1::zk_ace_replay(effect.policy_id, effect.replay_nullifier)
                        .map_err(|error| {
                            Error::InvariantViolation(
                                format!("verified ZK-ACE replay key is invalid: {error}").into(),
                            )
                        })?;
                if replay_key != expected_replay_key {
                    return Err(Error::InvariantViolation(
                        "native ZK-ACE effect changed its replay key".into(),
                    ));
                }
                if state_transaction
                    .world
                    .privacy_nullifiers
                    .get(&replay_key)
                    .is_some()
                {
                    return Err(invalid_privacy_parameter(
                        "verified ZK-ACE replay nullifier was already consumed",
                    ));
                }
                let replay_record = PrivacyStateItemRecordV1::zk_ace_verified_authorization(
                    policy.policy_id,
                    policy.record_digest,
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                )
                .map_err(invalid_privacy_parameter)?;
                let amount = Quantity::from(effect.amount);
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                super::asset::isi::execute_verified_privacy_public_balance_transfer(
                    state_transaction,
                    authority,
                    self.envelope.statement_digest,
                    &effect.asset_definition_id,
                    effect.public_balance_scope,
                    &effect.source,
                    &effect.destination,
                    amount,
                )?;
                state_transaction
                    .world
                    .privacy_nullifiers
                    .insert(replay_key, replay_record);
                Ok(())
            }
            VerifiedPrivacyLedgerEffectsV1::ZkAmsBatchAdmission(effect) => {
                let snapshot = zk_ams_snapshot.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native ZK-AMS batch effect has no trusted registry snapshot".into(),
                    )
                })?;
                let PrivacyStatementV1::IrohaZkAmsV1(statement) = &self.envelope.statement else {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS batch effect has a different statement type".into(),
                    ));
                };
                let PrivacyZkAmsActionV1::BatchAdmission(batch) = &statement.action else {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS batch effect has a provisioning statement".into(),
                    ));
                };
                let expected_next_epoch =
                    snapshot.current_epoch().checked_add(1).ok_or_else(|| {
                        Error::InvariantViolation("ZK-AMS registry epoch overflow".into())
                    })?;
                if effect.issuer_id != statement.issuer_id
                    || effect.policy_id != statement.policy_id
                    || effect.policy_digest != statement.policy_digest
                    || effect.issuer_policy_record_digest != snapshot.issuer_policy_record_digest()
                    || effect.registry_id != statement.registry_id
                    || effect.registry_record_digest != statement.registry_record_digest
                    || effect.current_root != snapshot.current_root()
                    || effect.current_epoch != snapshot.current_epoch()
                    || effect.next_root != batch.next_account_registry_root
                    || effect.next_epoch != expected_next_epoch
                    || effect.anchors != batch.anchors
                {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS batch effect is inconsistent with trusted state or its statement"
                            .into(),
                    ));
                }
                let expected_registry_record = zk_ams_registry_record_digest_v1(
                    effect.issuer_id,
                    effect.registry_id,
                    effect.policy_id,
                    effect.issuer_policy_record_digest,
                    effect.policy_digest,
                    snapshot.current_root(),
                    snapshot.current_epoch(),
                );
                if expected_registry_record != effect.registry_record_digest {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS batch effect carries a non-authoritative registry record"
                            .into(),
                    ));
                }
                let batch_size = u32::try_from(effect.anchors.len()).map_err(|_| {
                    Error::InvariantViolation(
                        "verified ZK-AMS anchor count cannot be represented".into(),
                    )
                })?;
                let mut computed_next_root = snapshot.current_root();
                let mut item_keys = Vec::with_capacity(effect.anchors.len().saturating_mul(2));
                let mut seen_item_keys = BTreeSet::new();
                for (index, anchor) in effect.anchors.iter().copied().enumerate() {
                    let anchor_index = u32::try_from(index).map_err(|_| {
                        Error::InvariantViolation(
                            "verified ZK-AMS anchor index cannot be represented".into(),
                        )
                    })?;
                    computed_next_root = zk_ams_registry_transition_root_v1(
                        effect.registry_id,
                        computed_next_root,
                        snapshot.current_epoch(),
                        expected_next_epoch,
                        batch_size,
                        anchor_index,
                        anchor,
                    );
                    let phc_key =
                        PrivacyCommitmentKeyV1::zk_ams_phc(snapshot.namespace(), anchor.phc_hash)
                            .map_err(|error| {
                            Error::InvariantViolation(
                                format!("verified ZK-AMS PHC key is invalid: {error}").into(),
                            )
                        })?;
                    let seed_key = PrivacyCommitmentKeyV1::zk_ams_seed_key(
                        snapshot.namespace(),
                        anchor.seed_public_key,
                    )
                    .map_err(|error| {
                        Error::InvariantViolation(
                            format!("verified ZK-AMS seed key is invalid: {error}").into(),
                        )
                    })?;
                    if !seen_item_keys.insert(phc_key) || !seen_item_keys.insert(seed_key) {
                        return Err(Error::InvariantViolation(
                            "verified ZK-AMS batch contains duplicate typed state keys".into(),
                        ));
                    }
                    if state_transaction
                        .world
                        .privacy_commitments
                        .get(&phc_key)
                        .is_some()
                        || state_transaction
                            .world
                            .privacy_commitments
                            .get(&seed_key)
                            .is_some()
                    {
                        return Err(invalid_privacy_parameter(
                            "verified ZK-AMS batch attempts to re-admit existing state",
                        ));
                    }
                    item_keys.push(phc_key);
                    item_keys.push(seed_key);
                }
                if computed_next_root != effect.next_root {
                    return Err(Error::InvariantViolation(
                        "verified ZK-AMS successor root is inconsistent".into(),
                    ));
                }
                let item_provenance = PrivacyStateItemRecordV1::zk_ams_verified_proof(
                    snapshot.bootstrap_digest(),
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                )
                .map_err(invalid_privacy_parameter)?;
                let root_provenance = PrivacyRootProvenanceV1::zk_ams_registry_successor(
                    snapshot.bootstrap_digest(),
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                    snapshot.current_epoch(),
                    snapshot.current_root(),
                )
                .map_err(invalid_privacy_parameter)?;
                let root_key = PrivacyRootKeyV1::new(
                    snapshot.namespace(),
                    PrivacyRootRoleV1::AccountRegistry,
                    expected_next_epoch,
                    computed_next_root,
                )
                .map_err(invalid_privacy_parameter)?;
                let head_key = PrivacyRootHeadKeyV1::new(
                    snapshot.namespace(),
                    PrivacyRootRoleV1::AccountRegistry,
                )
                .map_err(invalid_privacy_parameter)?;
                let removals = plan_privacy_root_history_update_v1(
                    &state_transaction.world.privacy_roots,
                    &[root_key],
                    state_transaction
                        .world
                        .privacy_consensus_policy
                        .get()
                        .admission_retained_root_count(),
                )
                .map_err(|error| {
                    invalid_privacy_parameter(format!(
                        "ZK-AMS AccountRegistry successor rejected: {error}"
                    ))
                })?;
                let retention_anchor = removals
                    .last()
                    .map(|key| PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root()))
                    .transpose()
                    .map_err(invalid_privacy_parameter)?
                    .or_else(|| snapshot.retention_anchor());
                let root_head = PrivacyRootHeadRecordV1::new(
                    expected_next_epoch,
                    computed_next_root,
                    root_provenance,
                    retention_anchor,
                )
                .map_err(invalid_privacy_parameter)?;
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                for key in removals {
                    state_transaction.world.privacy_roots.remove(key);
                }
                for key in item_keys {
                    state_transaction
                        .world
                        .privacy_commitments
                        .insert(key, item_provenance.clone());
                }
                state_transaction
                    .world
                    .privacy_roots
                    .insert(root_key, root_provenance);
                state_transaction
                    .world
                    .privacy_root_heads
                    .insert(head_key, root_head);
                Ok(())
            }
            VerifiedPrivacyLedgerEffectsV1::ZkAmsProvisionAccount(effect) => {
                let snapshot = zk_ams_snapshot.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native ZK-AMS provisioning effect has no trusted registry snapshot".into(),
                    )
                })?;
                let PrivacyStatementV1::IrohaZkAmsV1(statement) = &self.envelope.statement else {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS provisioning effect has a different statement type".into(),
                    ));
                };
                let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &statement.action else {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS provisioning effect has a batch statement".into(),
                    ));
                };
                if effect.issuer_id != statement.issuer_id
                    || effect.policy_id != statement.policy_id
                    || effect.policy_digest != statement.policy_digest
                    || effect.issuer_policy_record_digest != snapshot.issuer_policy_record_digest()
                    || effect.registry_id != statement.registry_id
                    || effect.registry_record_digest != statement.registry_record_digest
                    || effect.current_root != snapshot.current_root()
                    || effect.current_epoch != snapshot.current_epoch()
                    || effect.ring != provision.admitted_seed_key_ring
                    || effect.account_id != provision.account_id
                    || effect.key_image != provision.key_image
                {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS provisioning effect is inconsistent with trusted state or its statement"
                            .into(),
                    ));
                }
                let expected_registry_record = zk_ams_registry_record_digest_v1(
                    effect.issuer_id,
                    effect.registry_id,
                    effect.policy_id,
                    effect.issuer_policy_record_digest,
                    effect.policy_digest,
                    snapshot.current_root(),
                    snapshot.current_epoch(),
                );
                if expected_registry_record != effect.registry_record_digest {
                    return Err(Error::InvariantViolation(
                        "native ZK-AMS provisioning effect carries a non-authoritative registry record"
                            .into(),
                    ));
                }
                for seed_public_key in &effect.ring {
                    let seed_key = PrivacyCommitmentKeyV1::zk_ams_seed_key(
                        snapshot.namespace(),
                        *seed_public_key,
                    )
                    .map_err(|error| {
                        Error::InvariantViolation(
                            format!("verified ZK-AMS ring key is invalid: {error}").into(),
                        )
                    })?;
                    let record = state_transaction
                        .world
                        .privacy_commitments
                        .get(&seed_key)
                        .ok_or_else(|| {
                            invalid_privacy_parameter(
                                "verified ZK-AMS ring contains an unadmitted seed key",
                            )
                        })?;
                    record.validate().map_err(|error| {
                        Error::InvariantViolation(
                            format!("persisted ZK-AMS ring provenance is invalid: {error}").into(),
                        )
                    })?;
                    if !matches!(
                        record,
                        PrivacyStateItemRecordV1::ZkAmsVerifiedProof {
                            bootstrap_digest,
                            ..
                        } if *bootstrap_digest == snapshot.bootstrap_digest()
                    ) {
                        return Err(Error::InvariantViolation(
                            "verified ZK-AMS ring contains cross-bootstrap state".into(),
                        ));
                    }
                }
                let image_key =
                    PrivacyNullifierKeyV1::zk_ams_key_image(snapshot.namespace(), effect.key_image)
                        .map_err(|error| {
                            Error::InvariantViolation(
                                format!("verified ZK-AMS key image is invalid: {error}").into(),
                            )
                        })?;
                if state_transaction
                    .world
                    .privacy_nullifiers
                    .get(&image_key)
                    .is_some()
                {
                    return Err(invalid_privacy_parameter(
                        "verified ZK-AMS provisioning key image was already consumed",
                    ));
                }
                if state_transaction
                    .world
                    .accounts
                    .get(&effect.account_id)
                    .is_some()
                {
                    return Err(invalid_privacy_parameter(
                        "verified ZK-AMS provisioning target account already exists",
                    ));
                }
                super::domain::isi::ensure_controller_capabilities(
                    effect.account_id.controller(),
                    &state_transaction.crypto.allowed_signing,
                    &state_transaction.crypto.allowed_curve_ids,
                )?;
                let item_provenance = PrivacyStateItemRecordV1::zk_ams_verified_proof(
                    snapshot.bootstrap_digest(),
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                )
                .map_err(invalid_privacy_parameter)?;
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                Register::account(Account::new(effect.account_id.clone()))
                    .execute(authority, state_transaction)?;
                state_transaction
                    .world
                    .privacy_nullifiers
                    .insert(image_key, item_provenance);
                Ok(())
            }
            VerifiedPrivacyLedgerEffectsV1::AnonymousPgcPayment(effect) => {
                let snapshot = pgc_snapshot.as_ref().ok_or_else(|| {
                    Error::InvariantViolation(
                        "native Anonymous PGC effect has no trusted pool snapshot".into(),
                    )
                })?;
                let expected_next_epoch =
                    snapshot.current_epoch().checked_add(1).ok_or_else(|| {
                        Error::InvariantViolation(
                            "Anonymous PGC account-state epoch overflow".into(),
                        )
                    })?;
                if effect.namespace() != snapshot.namespace()
                    || effect.total_supply() != snapshot.invariant().total_supply()
                    || effect.current_root() != snapshot.current_root()
                    || effect.current_epoch() != snapshot.current_epoch()
                    || effect.next_epoch() != expected_next_epoch
                    || effect.accounts().len() != snapshot.accounts().len()
                    || effect
                        .accounts()
                        .iter()
                        .zip(snapshot.accounts())
                        .any(|(next, current)| next.public_key != current.public_key)
                {
                    return Err(Error::InvariantViolation(
                        "native Anonymous PGC verifier returned effects inconsistent with trusted state"
                            .into(),
                    ));
                }
                let computed_next_root = compute_privacy_pgc_account_state_root_v1(
                    effect.namespace(),
                    effect.next_epoch(),
                    effect.total_supply(),
                    effect.accounts(),
                )
                .map_err(|error| {
                    Error::InvariantViolation(
                        format!("verified Anonymous PGC successor table is not canonical: {error}")
                            .into(),
                    )
                })?;
                if computed_next_root != effect.next_root() {
                    return Err(Error::InvariantViolation(
                        "verified Anonymous PGC successor root is inconsistent".into(),
                    ));
                }
                let account_provenance = PrivacyPgcAccountProvenanceV1::verified_proof(
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                )
                .map_err(invalid_privacy_parameter)?;
                let pool_invariant_digest = snapshot
                    .invariant()
                    .digest(effect.namespace())
                    .map_err(|error| {
                        Error::InvariantViolation(
                            format!("verified Anonymous PGC pool invariant digest failed: {error}")
                                .into(),
                        )
                    })?;
                let root_provenance = PrivacyRootProvenanceV1::verified_pgc_successor(
                    self.envelope.statement_digest,
                    state_transaction.block_height(),
                    expected_action_index,
                    snapshot.current_epoch(),
                    snapshot.current_root(),
                    pool_invariant_digest,
                )
                .map_err(invalid_privacy_parameter)?;
                let mut seen_keys = BTreeSet::new();
                let mut account_updates = Vec::with_capacity(effect.accounts().len());
                for account in effect.accounts() {
                    let key = PrivacyPgcAccountKeyV1::new(effect.namespace(), account.public_key)
                        .map_err(invalid_privacy_parameter)?;
                    if !seen_keys.insert(key) {
                        return Err(Error::InvariantViolation(
                            "native Anonymous PGC successor contains duplicate account keys".into(),
                        ));
                    }
                    let state = PrivacyPgcAccountStateV1::new(
                        account.encrypted_balance,
                        effect.next_epoch(),
                        account_provenance,
                    )
                    .map_err(invalid_privacy_parameter)?;
                    account_updates.push((key, state));
                }
                let root_key = PrivacyRootKeyV1::new(
                    effect.namespace(),
                    PrivacyRootRoleV1::PgcAccountState,
                    effect.next_epoch(),
                    effect.next_root(),
                )
                .map_err(invalid_privacy_parameter)?;
                let head_key = PrivacyRootHeadKeyV1::new(
                    effect.namespace(),
                    PrivacyRootRoleV1::PgcAccountState,
                )
                .map_err(invalid_privacy_parameter)?;
                let removals = plan_privacy_root_history_update_v1(
                    &state_transaction.world.privacy_roots,
                    &[root_key],
                    state_transaction
                        .world
                        .privacy_consensus_policy
                        .get()
                        .current_limits
                        .retained_root_count,
                )
                .map_err(|error| {
                    invalid_privacy_parameter(format!(
                        "Anonymous PGC successor root rejected: {error}"
                    ))
                })?;
                let retention_anchor = removals
                    .last()
                    .map(|key| PrivacyRootRetentionAnchorV1::new(key.epoch(), key.root()))
                    .transpose()
                    .map_err(invalid_privacy_parameter)?
                    .or_else(|| snapshot.retention_anchor());
                let root_head = PrivacyRootHeadRecordV1::new(
                    effect.next_epoch(),
                    effect.next_root(),
                    root_provenance,
                    retention_anchor,
                )
                .map_err(invalid_privacy_parameter)?;
                state_transaction
                    .reserve_privacy_action(expected_action_index, encoded_action_bytes)?;
                for key in removals {
                    state_transaction.world.privacy_roots.remove(key);
                }
                for (key, state) in account_updates {
                    state_transaction
                        .world
                        .privacy_pgc_accounts
                        .insert(key, state);
                }
                state_transaction
                    .world
                    .privacy_roots
                    .insert(root_key, root_provenance);
                state_transaction
                    .world
                    .privacy_root_heads
                    .insert(head_key, root_head);
                Ok(())
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        privacy_engines::{
            anonymous_pgc::{
                AnonymousPgcPoolInvariantV1, TwistedElGamalKeyPairV1, add_ciphertexts,
                bootstrap::{AnonymousPgcBootstrapWitnessV1, prove_bootstrap},
                encrypt_with_randomness,
                payment::{
                    AnonymousPgcPaymentStatementV1, AnonymousPgcPaymentWitnessV1,
                    encrypt_signed_with_randomness, prove_payment,
                },
            },
            ivm_private_note::private_note_statement_fixture_v1,
            p256::SecretScalarV1,
            pq_masp::relation::test_fixtures::valid_fixture as pq_masp_fixture,
        },
        privacy_profiles::{CompiledPrivacyProfileErrorV1, compiled_privacy_profile_v1},
        privacy_verifier::{
            FcmpRuntimeFixtureForTest, ZkAmsRuntimeFixtureForTest, fcmp_runtime_fixture_for_test,
            zk_ams_runtime_fixture_for_test,
        },
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use core::num::NonZeroU64;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        NetworkId, Registrable,
        account::Account,
        asset::{AssetDefinition, AssetDefinitionId},
        block::BlockHeader,
        domain::Domain,
        privacy::{
            AnonymousPgcActivationLimitsV1, AnonymousPgcKOutOfNStatementV1,
            BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1, BOOTLE_LANTERN_RING_DEGREE_V1,
            BootleLanternAllowedAttributeValuesV1, BootleLanternIssuerPublicMatrixV1,
            BootleLanternPolynomialV1, PrivacyActiveLifecycleV1,
            PrivacyBootleLanternIssuerPolicyDigestV1, PrivacyConsensusLimitsV1, PrivacyIssuerIdV1,
            PrivacyIvmPrivateNotePoolBootstrapV1, PrivacyNamespaceScopeV1, PrivacyNamespaceV1,
            PrivacyP256CiphertextV1, PrivacyP256PointV1, PrivacyParameterDigestV1,
            PrivacyParameterIdV1, PrivacyPgcAccountBootstrapV1, PrivacyPgcAccountV1,
            PrivacyPgcBootstrapProofBytesV1, PrivacyPolicyDigestV1, PrivacyPolicyIdV1,
            PrivacyPoolIdV1, PrivacyPoolNamespaceV1, PrivacyPqMaspPoolBootstrapV1,
            PrivacyProofBytesV1, PrivacyProofEnvelopeV1, PrivacyProofManagedPoolBootstrapV1,
            PrivacyProofV1, PrivacyProposedLifecycleV1, PrivacyProtocolActivationLimitsV1,
            PrivacyProtocolIdV1, PrivacyRootPublicationV1, PrivacyRootV1,
            PrivacyStatementContextV1, PrivacyStatementDigestV1, PrivacyStatementV1,
            PrivacyTransactionIntentDigestV1, PrivacyTrustAnchorNamespaceV1,
            PrivacyTrustAnchorPolicyNamespaceV1, PrivacyX509CrlDerDigestV1,
            PrivacyX509CrlIssuerSpkiDigestV1, PrivacyX509ExtendedKeyUsageV1, PrivacyX509KeyUsageV1,
            PrivacyX509TrustStoreDigestV1, PrivacyZkAceIdentityCommitmentV1,
            PrivacyZkAcePolicyLifecycleV1, PrivacyZkAcePolicyRecordV1,
            PrivacyZkX509CertificatePolicyRecordDigestV1, PrivacyZkX509CertificatePolicyRecordV1,
            PrivacyZkX509CrlRecordDigestV1, PrivacyZkX509CrlRecordV1,
            PrivacyZkX509TrustAnchorRecordDigestV1, PrivacyZkX509TrustAnchorRecordV1,
            TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use iroha_test_samples::ALICE_ID;
    use mv::storage::Storage;
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    use sha2::{Digest, Sha256};
    use std::{str::FromStr as _, sync::OnceLock};
    const TEST_CHAIN_ID: &str = "taira-pgc-runtime-test";
    const TEST_GENESIS_HASH: [u8; 32] = [0x91; 32];
    const TEST_BLOCK_HEIGHT: u64 = 2;

    fn test_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(TEST_GENESIS_HASH),
        ))
    }
    fn activation_execution_state() -> State {
        use crate::sumeragi::{
            startup,
            test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let world = World::with(
            [],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(iroha_test_samples::BOB_ID.clone()).build(&iroha_test_samples::BOB_ID),
            ],
            [],
        );
        let config = TestChainConfig::new(world, 0);
        let account = AccountId::new(config.genesis_key.public_key().clone());
        let mode = config.consensus_mode;
        let prepared =
            CertifiedTestChain::prepare(config).expect("prepare actual governance genesis");
        let state = std::sync::Arc::try_unwrap(prepared.state)
            .unwrap_or_else(|_| panic!("unpublished governance State is unique"));
        startup::apply_genesis(
            &state,
            prepared.genesis.block().clone(),
            &account,
            mode.into(),
            None,
        )
        .expect("apply actual signed governance genesis");
        state
    }

    fn activation_execution_header(state: &State) -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(TEST_BLOCK_HEIGHT).unwrap(),
            state.view().latest_block_hash(),
            None,
            1_800_000_000_000,
            0,
        )
    }

    #[test]
    fn governed_registration_and_activation_share_one_state_transaction() {
        let state = activation_execution_state();
        let mut block = state.block(activation_execution_header(&state));
        let mut transaction = block.transaction();
        assert!(
            crate::executor::root_scope::execution_root_scope(&mut transaction).is_ok(),
            "governance matrix requires the authenticated ordinary execution root"
        );
        grant_governance(&mut transaction);
        let proposal = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("compiled profile")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: TEST_BLOCK_HEIGHT,
                },
            ));
        let key = PrivacyActivationKeyV1::new(proposal.protocol_id);
        crate::executor::Executor::Initial
            .execute_instruction(
                &mut transaction,
                &ALICE_ID,
                RegisterPrivacyProtocolActivationV1::new(proposal).into(),
            )
            .expect("authorized registration");
        assert_eq!(
            transaction.world.privacy_activations.get(&key),
            Some(&proposal)
        );
        let active = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
            proposed_at_height: TEST_BLOCK_HEIGHT,
            activated_at_height: TEST_BLOCK_HEIGHT,
            state_since_height: TEST_BLOCK_HEIGHT,
        });
        crate::executor::Executor::Initial
            .execute_instruction(
                &mut transaction,
                &ALICE_ID,
                TransitionPrivacyProtocolLifecycleV1::new(proposal.protocol_id, active).into(),
            )
            .expect("authorized same-transaction activation");
        let expected = PrivacyProtocolActivationRecordV1 {
            lifecycle: active,
            ..proposal
        };
        assert_eq!(
            transaction.world.privacy_activations.get(&key),
            Some(&expected)
        );
        transaction.apply();
        assert_eq!(block.world.privacy_activations.get(&key), Some(&expected));
        crate::privacy_state::validate_privacy_activations_at_committed_height_v1(
            &block.world.privacy_activations,
            TEST_BLOCK_HEIGHT,
        )
        .expect("same-block activation is a valid durable history");
    }
    #[test]
    fn explicit_activation_keeps_authority_height_and_transaction_rollback_checks() {
        let state = activation_execution_state();
        let mut block = state.block(activation_execution_header(&state));
        let proposal = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
            .expect("compiled profile")
            .activation_record(PrivacyProtocolLifecycleV1::Proposed(
                PrivacyProposedLifecycleV1 {
                    proposed_at_height: TEST_BLOCK_HEIGHT,
                },
            ));
        let key = PrivacyActivationKeyV1::new(proposal.protocol_id);
        {
            let mut transaction = block.transaction();
            assert!(
                crate::executor::root_scope::execution_root_scope(&mut transaction).is_ok(),
                "governance matrix requires the authenticated ordinary execution root"
            );
            let error = crate::executor::Executor::Initial
                .execute_instruction(
                    &mut transaction,
                    &ALICE_ID,
                    RegisterPrivacyProtocolActivationV1::new(proposal).into(),
                )
                .expect_err("post-genesis registration requires governance authority");
            assert!(format!("{error:?}").contains("CanEnactGovernance"));
            assert!(transaction.world.privacy_activations.get(&key).is_none());
            grant_governance(&mut transaction);
            crate::executor::Executor::Initial
                .execute_instruction(
                    &mut transaction,
                    &ALICE_ID,
                    RegisterPrivacyProtocolActivationV1::new(proposal).into(),
                )
                .expect("authorized registration");
            let active = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                proposed_at_height: TEST_BLOCK_HEIGHT,
                activated_at_height: TEST_BLOCK_HEIGHT,
                state_since_height: TEST_BLOCK_HEIGHT,
            });
            let error = crate::executor::Executor::Initial
                .execute_instruction(
                    &mut transaction,
                    &iroha_test_samples::BOB_ID,
                    TransitionPrivacyProtocolLifecycleV1::new(proposal.protocol_id, active).into(),
                )
                .expect_err("activation independently requires governance authority");
            assert!(format!("{error:?}").contains("CanEnactGovernance"));
            assert_eq!(
                transaction.world.privacy_activations.get(&key),
                Some(&proposal)
            );
            let future = PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                proposed_at_height: TEST_BLOCK_HEIGHT,
                activated_at_height: TEST_BLOCK_HEIGHT + 1,
                state_since_height: TEST_BLOCK_HEIGHT + 1,
            });
            crate::executor::Executor::Initial
                .execute_instruction(
                    &mut transaction,
                    &ALICE_ID,
                    TransitionPrivacyProtocolLifecycleV1::new(proposal.protocol_id, future).into(),
                )
                .expect_err("a signed activation cannot claim another block height");
            assert_eq!(
                transaction.world.privacy_activations.get(&key),
                Some(&proposal)
            );
            crate::executor::Executor::Initial
                .execute_instruction(
                    &mut transaction,
                    &ALICE_ID,
                    TransitionPrivacyProtocolLifecycleV1::new(proposal.protocol_id, active).into(),
                )
                .expect("valid explicit activation");
        }
        assert!(
            block.world.privacy_activations.get(&key).is_none(),
            "an unapplied transaction rolls back both registration and activation"
        );
    }
    struct KatRng {
        seed: [u8; 32],
        counter: u64,
    }
    impl KatRng {
        const fn new(seed: [u8; 32]) -> Self {
            Self { seed, counter: 0 }
        }
    }
    impl RngCore for KatRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0; 4];
            self.fill_bytes(&mut bytes);
            u32::from_be_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0; 8];
            self.fill_bytes(&mut bytes);
            u64::from_be_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(32) {
                let mut hash = Sha256::new();
                hash.update(b"iroha.privacy.pgc-runtime-test-rng.v1");
                hash.update(self.seed);
                hash.update(self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                let block: [u8; 32] = hash.finalize().into();
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }
    impl CryptoRng for KatRng {}
    fn secret(value: u64) -> SecretScalarV1 {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        SecretScalarV1::from_bytes(bytes).expect("canonical non-zero scalar")
    }
    include!("privacy/active_lifecycle_helper.rs");
    fn valid_bootstrap_instruction() -> BootstrapPrivacyPgcAccountsV1 {
        static INSTRUCTION: OnceLock<BootstrapPrivacyPgcAccountsV1> = OnceLock::new();
        INSTRUCTION
            .get_or_init(|| {
                let namespace = PrivacyNamespaceV1::new(
                    PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                    PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                        pool_id: PrivacyPoolIdV1::new([0xA1; 32]),
                    }),
                );
                let balances = vec![100_u32; 16];
                let total_supply = balances.iter().copied().sum();
                let mut key_pairs = (2_u64..18)
                    .map(|value| {
                        TwistedElGamalKeyPairV1::from_secret(secret(value)).expect("PGC key pair")
                    })
                    .collect::<Vec<_>>();
                key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
                let public_keys = key_pairs
                    .iter()
                    .map(TwistedElGamalKeyPairV1::public_key)
                    .collect::<Vec<_>>();
                let randomness = (0_u64..16)
                    .map(|index| secret(200 + index))
                    .collect::<Vec<_>>();
                let encrypted_balances = public_keys
                    .iter()
                    .copied()
                    .zip(&balances)
                    .zip(&randomness)
                    .map(|((public_key, balance), randomness)| {
                        encrypt_with_randomness(public_key, *balance, randomness)
                            .expect("PGC encrypted balance")
                    })
                    .collect::<Vec<_>>();
                let accounts = public_keys
                    .iter()
                    .zip(&encrypted_balances)
                    .map(|(public_key, encrypted_balance)| PrivacyPgcAccountV1 {
                        public_key: PrivacyP256PointV1::new(*public_key.as_point().as_bytes()),
                        encrypted_balance: PrivacyP256CiphertextV1 {
                            left: PrivacyP256PointV1::new(*encrypted_balance.left().as_bytes()),
                            right: PrivacyP256PointV1::new(*encrypted_balance.right().as_bytes()),
                        },
                    })
                    .collect::<Vec<_>>();
                let initial_epoch = 1;
                let initial_root = compute_privacy_pgc_account_state_root_v1(
                    namespace,
                    initial_epoch,
                    total_supply,
                    &accounts,
                )
                .expect("canonical PGC root");
                let bootstrap = PrivacyPgcAccountBootstrapV1 {
                    namespace,
                    initial_root,
                    initial_epoch,
                    total_supply,
                    accounts,
                };
                let bootstrap_digest = bootstrap.digest().expect("bootstrap digest");
                let namespace_encoding = norito::to_bytes(&namespace).expect("namespace encoding");
                let compiled =
                    compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
                        .expect("compiled Anonymous PGC profile");
                let parameters = AnonymousPgcParametersV1::get().expect("Anonymous PGC parameters");
                let statement = AnonymousPgcBootstrapStatementV1::new(
                    &namespace_encoding,
                    *initial_root.as_bytes(),
                    initial_epoch,
                    total_supply,
                    &public_keys,
                    &encrypted_balances,
                    TranscriptBindingV1 {
                        network_id: &TEST_GENESIS_HASH,
                        genesis_hash: TEST_GENESIS_HASH,
                        action_index: 0,
                        statement_digest: *bootstrap_digest.as_bytes(),
                        parameter_id: *compiled.parameter_id.as_bytes(),
                        parameter_digest: *compiled.parameter_digest.as_bytes(),
                        verifier_digest: *compiled.verifier_digest.as_bytes(),
                        statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
                        engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
                        generator_digest: parameters.generator_digest(),
                    },
                )
                .expect("native bootstrap statement");
                let witness = AnonymousPgcBootstrapWitnessV1 {
                    balances: &balances,
                    randomness: &randomness,
                };
                let proof = prove_bootstrap(&statement, &witness, &mut KatRng::new([0xB7; 32]))
                    .expect("native bootstrap proof")
                    .encode();
                BootstrapPrivacyPgcAccountsV1::new(
                    bootstrap,
                    PrivacyPgcBootstrapProofBytesV1::new(proof),
                )
            })
            .clone()
    }
    fn valid_payment_instruction() -> SubmitPrivacyProofV1 {
        static INSTRUCTION: OnceLock<SubmitPrivacyProofV1> = OnceLock::new();
        INSTRUCTION
            .get_or_init(|| {
                let bootstrap_instruction = valid_bootstrap_instruction();
                let bootstrap = &bootstrap_instruction.bootstrap;
                let compiled =
                    compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
                        .expect("compiled Anonymous PGC profile");
                let mut key_pairs = (2_u64..18)
                    .map(|value| {
                        TwistedElGamalKeyPairV1::from_secret(secret(value)).expect("PGC key pair")
                    })
                    .collect::<Vec<_>>();
                key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
                let public_keys = key_pairs
                    .iter()
                    .map(TwistedElGamalKeyPairV1::public_key)
                    .collect::<Vec<_>>();
                let current_balances = bootstrap
                    .accounts
                    .iter()
                    .zip(&public_keys)
                    .map(|(account, public_key)| {
                        assert_eq!(
                            account.public_key.as_bytes(),
                            public_key.as_point().as_bytes(),
                            "payment key order must equal the bootstrapped table"
                        );
                        TwistedElGamalCiphertextV1::from_sec1_bytes(
                            account.encrypted_balance.left.as_bytes(),
                            account.encrypted_balance.right.as_bytes(),
                        )
                        .expect("bootstrapped ciphertext")
                    })
                    .collect::<Vec<_>>();
                let sender_index = 7;
                let recipient_count = 2;
                let mut transfer_values = vec![0_i64; public_keys.len()];
                transfer_values[2] = 20;
                transfer_values[12] = 30;
                transfer_values[sender_index] = -50;
                let transfer_randomness = (0..public_keys.len())
                    .map(|index| {
                        secret(100 + u64::try_from(index).expect("payment fixture index fits u64"))
                    })
                    .collect::<Vec<_>>();
                let transfers = public_keys
                    .iter()
                    .copied()
                    .zip(&transfer_values)
                    .zip(&transfer_randomness)
                    .map(|((public_key, value), randomness)| {
                        encrypt_signed_with_randomness(public_key, *value, randomness)
                            .expect("signed transfer ciphertext")
                    })
                    .collect::<Vec<_>>();
                let next_balances = current_balances
                    .iter()
                    .copied()
                    .zip(&transfers)
                    .map(|(current, transfer)| {
                        add_ciphertexts(current, *transfer).expect("successor balance")
                    })
                    .collect::<Vec<_>>();
                let transfer_ciphertexts = transfers
                    .iter()
                    .map(|ciphertext| PrivacyP256CiphertextV1 {
                        left: PrivacyP256PointV1::new(*ciphertext.left().as_bytes()),
                        right: PrivacyP256PointV1::new(*ciphertext.right().as_bytes()),
                    })
                    .collect::<Vec<_>>();
                let next_accounts = public_keys
                    .iter()
                    .zip(&next_balances)
                    .map(|(public_key, ciphertext)| PrivacyPgcAccountV1 {
                        public_key: PrivacyP256PointV1::new(*public_key.as_point().as_bytes()),
                        encrypted_balance: PrivacyP256CiphertextV1 {
                            left: PrivacyP256PointV1::new(*ciphertext.left().as_bytes()),
                            right: PrivacyP256PointV1::new(*ciphertext.right().as_bytes()),
                        },
                    })
                    .collect::<Vec<_>>();
                let next_epoch = bootstrap.initial_epoch + 1;
                let next_root = compute_privacy_pgc_account_state_root_v1(
                    bootstrap.namespace,
                    next_epoch,
                    bootstrap.total_supply,
                    &next_accounts,
                )
                .expect("successor account root");
                let context = PrivacyStatementContextV1 {
                    network_id: test_network_id(),
                    action_index: 0,
                    transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0xD0; 32]),
                    parameter_id: compiled.parameter_id,
                    parameter_digest: compiled.parameter_digest,
                    verifier_digest: compiled.verifier_digest,
                    statement_schema_digest: compiled.statement_schema_digest,
                    engine_manifest_digest: compiled.engine_manifest_digest,
                };
                let statement =
                    PrivacyStatementV1::AnonymousPgcKOutOfNV1(AnonymousPgcKOutOfNStatementV1 {
                        context,
                        asset_definition_id: AssetDefinitionId::derive_from_components(
                            DomainId::try_new("privacy", "universal").expect("privacy domain"),
                            Name::from_str("pgc_cash").expect("asset name"),
                        ),
                        pool_id: PrivacyPoolIdV1::new([0xA1; 32]),
                        account_state_root: bootstrap.initial_root,
                        account_state_root_epoch: bootstrap.initial_epoch,
                        next_account_state_root: next_root,
                        next_account_state_root_epoch: next_epoch,
                        anonymity_set_public_keys: bootstrap
                            .accounts
                            .iter()
                            .map(|account| account.public_key)
                            .collect(),
                        transfer_ciphertexts,
                        recipient_count: u32::try_from(recipient_count)
                            .expect("recipient count fits u32"),
                    });
                let statement_digest = statement.digest().expect("payment statement digest");
                let parameters = AnonymousPgcParametersV1::get().expect("Anonymous PGC parameters");
                let bootstrap_digest = bootstrap.digest().expect("bootstrap digest");
                let bootstrap_proof_digest = bootstrap_instruction
                    .proof
                    .digest()
                    .expect("bootstrap proof digest");
                let pool_invariant = AnonymousPgcPoolInvariantV1::new(
                    bootstrap.total_supply,
                    *bootstrap_digest.as_bytes(),
                    *bootstrap_proof_digest.as_bytes(),
                )
                .expect("native pool invariant");
                let native_statement = AnonymousPgcPaymentStatementV1::new(
                    &public_keys,
                    &transfers,
                    &current_balances,
                    recipient_count,
                    pool_invariant,
                    TranscriptBindingV1 {
                        network_id: &TEST_GENESIS_HASH,
                        genesis_hash: TEST_GENESIS_HASH,
                        action_index: 0,
                        statement_digest: *statement_digest.as_bytes(),
                        parameter_id: *compiled.parameter_id.as_bytes(),
                        parameter_digest: *compiled.parameter_digest.as_bytes(),
                        verifier_digest: *compiled.verifier_digest.as_bytes(),
                        statement_schema_digest: *compiled.statement_schema_digest.as_bytes(),
                        engine_manifest_digest: *compiled.engine_manifest_digest.as_bytes(),
                        generator_digest: parameters.generator_digest(),
                    },
                )
                .expect("native payment statement");
                let witness = AnonymousPgcPaymentWitnessV1 {
                    transfer_values: &transfer_values,
                    transfer_randomness: &transfer_randomness,
                    sender_index,
                    sender_secret: key_pairs[sender_index].secret_scalar(),
                };
                let proof =
                    prove_payment(&native_statement, &witness, &mut KatRng::new([0xC7; 32]))
                        .expect("native payment proof")
                        .encode();
                SubmitPrivacyProofV1::new(PrivacyProofEnvelopeV1 {
                    wire_magic: iroha_data_model::privacy::PrivacyProofWireMagicV1::default(),
                    catalog_commitment:
                        iroha_data_model::privacy::PrivacyExact12CatalogCommitmentV1::default(),
                    protocol_id: compiled.protocol_id,
                    proof_system_id: compiled.proof_system_id,
                    engine_id: compiled.engine_id,
                    parameter_id: compiled.parameter_id,
                    parameter_digest: compiled.parameter_digest,
                    verifier_digest: compiled.verifier_digest,
                    statement_schema_digest: compiled.statement_schema_digest,
                    engine_manifest_digest: compiled.engine_manifest_digest,
                    statement_digest,
                    statement,
                    proof: PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(proof)),
                })
            })
            .clone()
    }
    fn bind_submit_privacy_instruction(
        transaction: &mut StateTransaction<'_, '_>,
        instruction: &SubmitPrivacyProofV1,
    ) {
        let digest = instruction
            .envelope
            .statement
            .context()
            .transaction_intent_digest;
        let submission_hash = crate::privacy::privacy_signed_submission_hash_v1(instruction)
            .expect("privacy submission encodes canonically");
        transaction.bind_privacy_transaction_intent_v1(Some((digest, submission_hash)));
    }
    fn bind_payment_instruction(
        transaction: &mut StateTransaction<'_, '_>,
        instruction: &SubmitPrivacyProofV1,
    ) {
        bind_submit_privacy_instruction(transaction, instruction);
    }
    fn execute_privacy_proof_after_admission_for_test(
        instruction: SubmitPrivacyProofV1,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        // Exercise the same intent binding, resource preflight, native verifier, and state
        // transition as Execute. This component fixture supplies an exact compiled activation;
        // it does not construct or claim the separate Exact12 deployment qualification.
        let submission = PreparedPrivacySubmissionV1::prepare(instruction, state_transaction)?;
        let activation = *state_transaction
            .world
            .privacy_activations
            .get(&PrivacyActivationKeyV1::new(
                submission.envelope.protocol_id,
            ))
            .expect("proof execution fixture has its exact protocol activation");
        assert_eq!(activation.protocol_id, submission.envelope.protocol_id);
        validate_compiled_privacy_activation_v1(&activation)
            .expect("proof execution fixture has exact compiled cryptographic bindings");
        submission.execute_after_admission(authority, state_transaction, activation)
    }
    fn install_synthetic_privacy_genesis_hash(state: &mut State, genesis_hash: [u8; 32]) {
        assert_eq!(
            state.network_id.as_bytes(),
            &genesis_hash,
            "privacy fixtures must bind their runtime network identity to the committed genesis"
        );
        // These protocol fixtures retain a synthetic committed genesis hash without a Kura block.
        // Hydrate the genuinely empty DA projection first so block construction never asks the
        // blank store for that synthetic body.
        state
            .ensure_da_indexes_hydrated()
            .expect("blank privacy-test Kura has an empty DA projection");
        state.push_block_hash_for_testing(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(genesis_hash),
        ));
    }
    fn state_with_activation(lifecycle: PrivacyProtocolLifecycleV1) -> State {
        let activation = compiled_privacy_profile_v1(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)
            .expect("compiled Anonymous PGC profile")
            .activation_record(lifecycle);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let mut world = World::with([], [alice], []);
        world.privacy_activations.insert(
            PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1),
            activation,
        );
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            TEST_CHAIN_ID.into(),
            test_network_id(),
        );
        install_synthetic_privacy_genesis_hash(&mut state, TEST_GENESIS_HASH);
        state
    }
    fn bootle_lantern_public_matrix(seed: usize) -> BootleLanternIssuerPublicMatrixV1 {
        let first_column = core::array::from_fn(|block| BootleLanternPolynomialV1 {
            coefficients: (0..BOOTLE_LANTERN_RING_DEGREE_V1)
                .map(|coefficient| {
                    u16::try_from(
                        (seed + block * BOOTLE_LANTERN_RING_DEGREE_V1 + coefficient) % 12_288 + 1,
                    )
                    .expect("fixture residue fits u16")
                })
                .collect(),
        });
        BootleLanternIssuerPublicMatrixV1::from_r512_first_column_blocks_v1(&first_column)
            .expect("canonical degree-512 multiplication matrix")
    }
    fn bootle_lantern_policy(
        epoch: u64,
        lifecycle: BootleLanternIssuerPolicyLifecycleV1,
    ) -> BootleLanternIssuerPolicyV1 {
        let mut policy = BootleLanternIssuerPolicyV1 {
            issuer_id: PrivacyIssuerIdV1::new([0xB1; 32]),
            policy_id: PrivacyPolicyIdV1::new([0xB2; 32]),
            epoch,
            lifecycle,
            issuer_parameter_id: PrivacyParameterIdV1::new([0xB3; 32]),
            issuer_parameter_digest: PrivacyParameterDigestV1::new([0; 32]),
            issuer_public_matrix: bootle_lantern_public_matrix(1),
            required_disclosure_bitmap: 0,
            allowed_values: vec![
                BootleLanternAllowedAttributeValuesV1 { values: Vec::new() };
                BOOTLE_LANTERN_ATTRIBUTE_COUNT_V1
            ],
            record_digest: PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]),
        };
        policy.issuer_parameter_digest = policy
            .computed_issuer_parameter_digest()
            .expect("canonical Bootle/Lantern issuer matrix");
        policy.record_digest = policy
            .computed_record_digest()
            .expect("canonical Bootle/Lantern policy");
        policy.validate().expect("valid Bootle/Lantern policy");
        policy
    }
    fn bootle_lantern_statement(
        policy: &BootleLanternIssuerPolicyV1,
    ) -> IrohaBootleLanternAnoncredStatementV1 {
        IrohaBootleLanternAnoncredStatementV1 {
            context: PrivacyStatementContextV1 {
                network_id: test_network_id(),
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0xB4; 32]),
                parameter_id: PrivacyParameterIdV1::new([0xB5; 32]),
                parameter_digest: PrivacyParameterDigestV1::new([0xB6; 32]),
                verifier_digest: iroha_data_model::privacy::PrivacyVerifierDigestV1::new(
                    [0xB7; 32],
                ),
                statement_schema_digest:
                    iroha_data_model::privacy::PrivacyStatementSchemaDigestV1::new([0xB8; 32]),
                engine_manifest_digest:
                    iroha_data_model::privacy::PrivacyEngineManifestDigestV1::new([0xB9; 32]),
            },
            issuer_id: policy.issuer_id,
            policy_id: policy.policy_id,
            issuer_policy_epoch: policy.epoch,
            issuer_policy_record_digest: policy.record_digest,
            issuer_parameter_id: policy.issuer_parameter_id,
            issuer_parameter_digest: policy.issuer_parameter_digest,
            disclosures: Vec::new(),
        }
    }
    fn rotate_bootle_lantern_policy(
        current: &BootleLanternIssuerPolicyV1,
    ) -> BootleLanternIssuerPolicyV1 {
        let mut successor = current.clone();
        successor.epoch = current
            .epoch
            .checked_add(1)
            .expect("fixture epoch advances");
        successor.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Active;
        successor.issuer_parameter_id.0[0] ^= 1;
        successor.issuer_public_matrix = bootle_lantern_public_matrix(701);
        successor.issuer_parameter_digest = successor
            .computed_issuer_parameter_digest()
            .expect("rotated issuer matrix");
        successor.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        successor.record_digest = successor
            .computed_record_digest()
            .expect("rotated policy digest");
        successor
            .validate_rotation_successor(current)
            .expect("canonical active successor");
        successor
    }
    fn revoke_bootle_lantern_policy(
        current: &BootleLanternIssuerPolicyV1,
    ) -> BootleLanternIssuerPolicyV1 {
        let mut successor = current.clone();
        successor.epoch = current
            .epoch
            .checked_add(1)
            .expect("fixture epoch advances");
        successor.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Revoked;
        successor.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        successor.record_digest = successor
            .computed_record_digest()
            .expect("revoked policy digest");
        successor
            .validate_revocation_successor(current)
            .expect("canonical terminal successor");
        successor
    }
    fn state_with_exact_bootle_lantern_activation() -> State {
        let protocol_id = PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1;
        let activation = compiled_privacy_profile_v1(protocol_id)
            .expect("compiled Bootle/Lantern profile")
            .activation_record(active_lifecycle());
        validate_compiled_privacy_activation_v1(&activation)
            .expect("exact compiled Bootle/Lantern activation");
        let domain_id = DomainId::try_new("privacy", "universal").expect("domain");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let mut world = World::with([domain], [alice], []);
        world
            .privacy_activations
            .insert(PrivacyActivationKeyV1::new(protocol_id), activation);
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            TEST_CHAIN_ID.into(),
            test_network_id(),
        );
        install_synthetic_privacy_genesis_hash(&mut state, TEST_GENESIS_HASH);
        state
    }
    fn zk_ace_asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("domain"),
            Name::from_str("asset").expect("asset name"),
        )
    }
    fn zk_ace_policy(
        epoch: u64,
        identity_byte: u8,
        lifecycle: PrivacyZkAcePolicyLifecycleV1,
    ) -> PrivacyZkAcePolicyRecordV1 {
        PrivacyZkAcePolicyRecordV1::new(
            PrivacyPolicyIdV1::new([0xA1; 32]),
            PrivacyZkAceIdentityCommitmentV1::new([u64::from(identity_byte); 6])
                .expect("fixture byte is a canonical Goldilocks element"),
            PrivacyPolicyDigestV1::new([0xA3; 32]),
            epoch,
            zk_ace_asset_definition_id(),
            vec![ALICE_ID.clone()],
            lifecycle,
        )
        .expect("canonical ZK-ACE policy fixture")
    }
    fn valid_zk_ace_policy() -> PrivacyZkAcePolicyRecordV1 {
        zk_ace_policy(1, 0xA2, PrivacyZkAcePolicyLifecycleV1::Active)
    }
    fn x509_trust_anchor_id() -> PrivacyIssuerIdV1 {
        PrivacyIssuerIdV1::new([0xC1; 32])
    }
    fn x509_policy_id() -> PrivacyPolicyIdV1 {
        PrivacyPolicyIdV1::new([0xC2; 32])
    }
    fn x509_ca_namespace() -> PrivacyNamespaceV1 {
        PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            PrivacyNamespaceScopeV1::TrustAnchor(PrivacyTrustAnchorNamespaceV1 {
                trust_anchor_id: x509_trust_anchor_id(),
            }),
        )
    }
    fn x509_namespace() -> PrivacyNamespaceV1 {
        PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            PrivacyNamespaceScopeV1::TrustAnchorPolicy(PrivacyTrustAnchorPolicyNamespaceV1 {
                trust_anchor_id: x509_trust_anchor_id(),
                policy_id: x509_policy_id(),
            }),
        )
    }
    fn x509_trust_anchor(
        epoch: u64,
        trust_store_byte: u8,
        previous: Option<PrivacyZkX509TrustAnchorRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509TrustAnchorRecordV1 {
        let ca_membership_root_epoch = match lifecycle {
            PrivacyZkX509RecordLifecycleV1::Active => epoch,
            PrivacyZkX509RecordLifecycleV1::Revoked => epoch.saturating_sub(1),
        };
        PrivacyZkX509TrustAnchorRecordV1::new(
            x509_trust_anchor_id(),
            epoch,
            PrivacyX509TrustStoreDigestV1::new([trust_store_byte; 32]),
            PrivacyRootV1::new([trust_store_byte.wrapping_add(1); 32]),
            ca_membership_root_epoch,
            previous,
            lifecycle,
        )
        .expect("canonical X.509 trust-anchor fixture")
    }
    fn x509_policy(
        epoch: u64,
        policy_byte: u8,
        disclosures: Vec<u8>,
        previous: Option<PrivacyZkX509CertificatePolicyRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509CertificatePolicyRecordV1 {
        PrivacyZkX509CertificatePolicyRecordV1::new(
            x509_trust_anchor_id(),
            x509_policy_id(),
            epoch,
            PrivacyPolicyDigestV1::new([policy_byte; 32]),
            PrivacyX509KeyUsageV1 {
                digital_signature: true.into(),
                content_commitment: false.into(),
                key_encipherment: false.into(),
                key_agreement: false.into(),
            },
            vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            disclosures,
            previous,
            lifecycle,
        )
        .expect("canonical X.509 certificate-policy fixture")
    }
    #[allow(clippy::too_many_arguments)]
    fn x509_crl(
        record_epoch: u64,
        crl_number: u64,
        der_byte: u8,
        this_update_unix_seconds: u64,
        next_update_unix_seconds: u64,
        _root_byte: u8,
        previous: Option<PrivacyZkX509CrlRecordDigestV1>,
        lifecycle: PrivacyZkX509RecordLifecycleV1,
    ) -> PrivacyZkX509CrlRecordV1 {
        PrivacyZkX509CrlRecordV1::new(
            x509_trust_anchor_id(),
            x509_policy_id(),
            record_epoch,
            crl_number,
            PrivacyX509CrlDerDigestV1::new([der_byte; 32]),
            PrivacyX509CrlIssuerSpkiDigestV1::new([0xE1; 32]),
            this_update_unix_seconds,
            next_update_unix_seconds,
            previous,
            lifecycle,
        )
        .expect("canonical X.509 signed-CRL fixture")
    }
    fn state_without_zk_ace_activation() -> State {
        let domain_id = DomainId::try_new("privacy", "universal").expect("domain");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let asset_definition = AssetDefinition::numeric(
            zk_ace_asset_definition_id(),
            "asset".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let world = World::with([domain], [alice], [asset_definition]);
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            TEST_CHAIN_ID.into(),
            test_network_id(),
        );
        install_synthetic_privacy_genesis_hash(&mut state, TEST_GENESIS_HASH);
        state
    }
    fn test_header() -> BlockHeader {
        test_header_at(TEST_BLOCK_HEIGHT)
    }
    fn test_header_at(height: u64) -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(height).expect("non-zero height"),
            None,
            None,
            1_800_000_000_000 + height - TEST_BLOCK_HEIGHT,
            0,
        )
    }
    fn state_with_fcmp_runtime_fixture(fixture: &FcmpRuntimeFixtureForTest) -> State {
        let PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) = &fixture.envelope.statement
        else {
            unreachable!("FCMP++ runtime fixture carries its typed statement")
        };
        let domain_id = DomainId::try_new("privacy", "universal").expect("privacy domain");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let asset_definition = AssetDefinition::numeric(
            statement.asset_definition_id.clone(),
            "fcmp_asset".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let mut world = World::with([domain], [alice], [asset_definition]);
        world.privacy_activations.insert(
            PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1),
            fixture.activation,
        );
        let snapshot = &fixture.snapshot;
        let namespace = snapshot.namespace();
        let bootstrap = snapshot.bootstrap().clone();
        let bootstrap_digest = snapshot.bootstrap_digest();
        let admitted_at_height = snapshot.bootstrap_admitted_at_height();
        let config_key = PrivacyCommitmentKeyV1::proof_managed_pool_config(namespace)
            .expect("FCMP++ config key");
        world.privacy_commitments.insert(
            config_key,
            PrivacyStateItemRecordV1::proof_managed_pool_bootstrap(
                bootstrap.clone(),
                bootstrap_digest,
                snapshot.initial_root(),
                admitted_at_height,
            )
            .expect("FCMP++ bootstrap configuration"),
        );
        for (position, output) in bootstrap
            .initial_fcmp_outputs()
            .expect("FCMP++ bootstrap outputs")
            .iter()
            .copied()
            .enumerate()
        {
            world.privacy_commitments.insert(
                PrivacyCommitmentKeyV1::fcmp_output(namespace, output.output_id())
                    .expect("FCMP++ bootstrap output key"),
                PrivacyStateItemRecordV1::fcmp_bootstrap_output(
                    bootstrap_digest,
                    output,
                    u64::try_from(position).expect("FCMP++ bootstrap position"),
                    admitted_at_height,
                )
                .expect("FCMP++ bootstrap output"),
            );
        }
        let root_provenance = PrivacyRootProvenanceV1::proof_managed_pool_bootstrap(
            bootstrap_digest,
            PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
            admitted_at_height,
        )
        .expect("FCMP++ bootstrap root provenance");
        world.privacy_roots.insert(
            PrivacyRootKeyV1::new(
                namespace,
                snapshot.root_role(),
                snapshot.current_epoch(),
                snapshot.current_root(),
            )
            .expect("FCMP++ bootstrap root key"),
            root_provenance,
        );
        world.privacy_root_heads.insert(
            PrivacyRootHeadKeyV1::new(namespace, snapshot.root_role())
                .expect("FCMP++ bootstrap head key"),
            PrivacyRootHeadRecordV1::new(
                snapshot.current_epoch(),
                snapshot.current_root(),
                root_provenance,
                None,
            )
            .expect("FCMP++ bootstrap root head"),
        );
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            TEST_CHAIN_ID.into(),
            fixture.network_id,
        );
        install_synthetic_privacy_genesis_hash(&mut state, fixture.genesis_hash);
        state
    }
    fn fcmp_test_header(fixture: &FcmpRuntimeFixtureForTest) -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(fixture.current_height).expect("non-zero FCMP++ height"),
            None,
            None,
            fixture.block_timestamp_ms,
            0,
        )
    }
    fn grant_governance(state_transaction: &mut StateTransaction<'_, '_>) {
        state_transaction
            .world
            .add_account_permission(&ALICE_ID, Permission::from(CanEnactGovernance));
    }
    fn privacy_map_counts(
        state_transaction: &StateTransaction<'_, '_>,
    ) -> (usize, usize, usize, usize) {
        (
            state_transaction
                .world
                .privacy_pgc_pool_invariants
                .iter()
                .count(),
            state_transaction.world.privacy_pgc_accounts.iter().count(),
            state_transaction.world.privacy_roots.iter().count(),
            state_transaction.world.privacy_root_heads.iter().count(),
        )
    }
    #[derive(Clone, Debug, PartialEq)]
    struct ProofManagedStateSnapshot {
        roots: Vec<Vec<u8>>,
        root_heads: Vec<Vec<u8>>,
        nullifiers: Vec<Vec<u8>>,
        commitments: Vec<Vec<u8>>,
        config: Option<PrivacyStateItemRecordV1>,
        budget: (u32, u64, u32, u64),
    }
    fn proof_managed_state_snapshot(
        state_transaction: &StateTransaction<'_, '_>,
        config_key: PrivacyCommitmentKeyV1,
    ) -> ProofManagedStateSnapshot {
        ProofManagedStateSnapshot {
            roots: state_transaction
                .world
                .privacy_roots
                .iter()
                .map(|(key, value)| {
                    norito::to_bytes(&(*key, value.clone())).expect("root snapshot encoding")
                })
                .collect(),
            root_heads: state_transaction
                .world
                .privacy_root_heads
                .iter()
                .map(|(key, value)| {
                    norito::to_bytes(&(*key, value.clone())).expect("root-head snapshot encoding")
                })
                .collect(),
            nullifiers: state_transaction
                .world
                .privacy_nullifiers
                .iter()
                .map(|(key, value)| {
                    norito::to_bytes(&(*key, value.clone())).expect("nullifier snapshot encoding")
                })
                .collect(),
            commitments: state_transaction
                .world
                .privacy_commitments
                .iter()
                .map(|(key, value)| {
                    norito::to_bytes(&(*key, value.clone())).expect("commitment snapshot encoding")
                })
                .collect(),
            config: state_transaction
                .world
                .privacy_commitments
                .get(&config_key)
                .cloned(),
            budget: state_transaction.privacy_budget_for_testing(),
        }
    }
    fn smart_contract_parameter_message(error: &Error) -> &str {
        let Error::InvalidParameter(InvalidParameterError::SmartContract(message)) = error else {
            panic!("expected a typed smart-contract parameter error, got {error:?}");
        };
        message
    }
    fn assert_empty_and_unbudgeted(state_transaction: &StateTransaction<'_, '_>) {
        assert_eq!(privacy_map_counts(state_transaction), (0, 0, 0, 0));
        assert_eq!(state_transaction.privacy_budget_for_testing(), (0, 0, 0, 0));
    }
    fn assert_proof_managed_submit_rejection_is_atomic(
        transaction: &mut StateTransaction<'_, '_>,
        instruction: SubmitPrivacyProofV1,
        config_key: PrivacyCommitmentKeyV1,
        expected_error: &str,
    ) {
        let before = proof_managed_state_snapshot(transaction, config_key);
        bind_submit_privacy_instruction(transaction, &instruction);
        let error =
            execute_privacy_proof_after_admission_for_test(instruction, &ALICE_ID, transaction)
                .expect_err("adversarial proof-managed submission must reject");
        assert!(
            format!("{error:?}").contains(expected_error),
            "unexpected proof-managed rejection: {error:?}"
        );
        assert_eq!(
            proof_managed_state_snapshot(transaction, config_key),
            before,
            "rejected submission mutated an exact root, head, nullifier, commitment/frontier, configuration, or budget byte: {error:?}"
        );
    }
    include!("privacy/core_state_tests.rs");
    include!("privacy/role_dispatch_tests.rs");
    #[test]
    fn private_note_apply_rejections_preserve_every_proof_managed_record() {
        let (mut statement, input_commitment) = private_note_statement_fixture_v1();
        let bootstrap = PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
            PrivacyIvmPrivateNotePoolBootstrapV1 {
                pool_id: statement.pool_id,
                asset_definition_id: statement.asset_definition_id.clone(),
                public_balance_scope: statement.public_balance_scope,
                reserve_account: ALICE_ID.clone(),
                program_id: statement.program_id,
                initial_note_commitments: vec![input_commitment],
            },
        );
        let snapshot = PrivacyProofManagedPoolSnapshotV1::canonical_private_note_bootstrap_for_test(
            bootstrap.clone(),
        );
        statement.state_root = snapshot.current_root();
        statement.root_epoch = snapshot.current_epoch();
        statement.execution_epoch = snapshot.current_epoch();
        statement.action_digest = iroha_data_model::privacy::PrivacyActionDigestV1::new([0; 32]);
        statement.action_digest = statement
            .computed_action_digest()
            .expect("canonical private-IVM action digest");
        let successor = snapshot
            .derive_note_successor(&statement.output_commitments)
            .expect("private-IVM successor");
        let statement_digest = PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement.clone())
            .digest()
            .expect("private-IVM statement digest");
        let domain_id = DomainId::try_new("privacy", "universal").expect("domain");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let asset_definition = AssetDefinition::numeric(
            statement.asset_definition_id.clone(),
            "ivmnote".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let world = World::with([domain], [alice], [asset_definition]);
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            TEST_CHAIN_ID.into(),
            test_network_id(),
        );
        install_synthetic_privacy_genesis_hash(&mut state, TEST_GENESIS_HASH);
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        let config_key = PrivacyCommitmentKeyV1::proof_managed_pool_config(snapshot.namespace())
            .expect("private-IVM config key");
        let config_record = PrivacyStateItemRecordV1::proof_managed_pool_bootstrap(
            bootstrap,
            snapshot.bootstrap_digest(),
            snapshot.initial_root(),
            1,
        )
        .expect("private-IVM config record");
        transaction
            .world
            .privacy_commitments
            .insert(config_key, config_record);
        let reserve_asset_id = AssetId::with_scope(
            statement.asset_definition_id.clone(),
            ALICE_ID.clone(),
            statement.public_balance_scope,
        );
        let custody_owner = PrivacyPublicReserveOwnerV1::PrivateIvm {
            namespace: snapshot.namespace(),
            bootstrap_digest: snapshot.bootstrap_digest(),
        };
        transaction.world.privacy_commitments.insert(
            PrivacyCommitmentKeyV1::public_reserve_custody(
                custody_owner.protocol_id(),
                &reserve_asset_id,
            )
            .expect("private-IVM reserve key"),
            PrivacyStateItemRecordV1::public_reserve_custody(reserve_asset_id, custody_owner)
                .expect("private-IVM reserve row"),
        );
        let genesis_key = PrivacyCommitmentKeyV1::proof_managed_pool_commitment(
            snapshot.namespace(),
            input_commitment,
        )
        .expect("private-IVM genesis commitment key");
        transaction.world.privacy_commitments.insert(
            genesis_key,
            PrivacyStateItemRecordV1::proof_managed_pool_bootstrap_commitment(
                snapshot.bootstrap_digest(),
                0,
                1,
            )
            .expect("private-IVM genesis commitment record"),
        );
        let root_provenance = PrivacyRootProvenanceV1::proof_managed_pool_bootstrap(
            snapshot.bootstrap_digest(),
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            1,
        )
        .expect("private-IVM root provenance");
        let root_key = PrivacyRootKeyV1::new(
            snapshot.namespace(),
            snapshot.root_role(),
            snapshot.current_epoch(),
            snapshot.current_root(),
        )
        .expect("private-IVM root key");
        transaction
            .world
            .privacy_roots
            .insert(root_key, root_provenance);
        transaction.world.privacy_root_heads.insert(
            PrivacyRootHeadKeyV1::new(snapshot.namespace(), snapshot.root_role())
                .expect("private-IVM head key"),
            PrivacyRootHeadRecordV1::new(
                snapshot.current_epoch(),
                snapshot.current_root(),
                root_provenance,
                None,
            )
            .expect("private-IVM head"),
        );
        let transition = || VerifiedProofManagedPoolTransitionV1::IvmPrivateNote {
            nullifiers: statement.nullifiers.clone(),
            output_commitments: statement.output_commitments.clone(),
            successor_state: successor.clone(),
        };
        let effect = |next_root| {
            VerifiedProofManagedPoolLedgerEffectV1::from_test_parts(
                VerifiedProofManagedPoolLedgerEffectTestPartsV1 {
                    namespace: snapshot.namespace(),
                    bootstrap_digest: snapshot.bootstrap_digest(),
                    asset_definition_id: statement.asset_definition_id.clone(),
                    current_root: snapshot.current_root(),
                    current_epoch: snapshot.current_epoch(),
                    next_root,
                    next_epoch: successor.epoch(),
                    transition: transition(),
                    value_balance: Some(statement.value_balance),
                    public_balance_scope: Some(statement.public_balance_scope),
                },
            )
        };
        let assert_atomic_rejection =
            |effect: &VerifiedProofManagedPoolLedgerEffectV1,
             transaction: &StateTransaction<'_, '_>| {
                let before = proof_managed_state_snapshot(transaction, config_key);
                let error = prepare_proof_managed_note_apply_v1(
                    ProofManagedNoteApplyContextV1 {
                        effect,
                        snapshot: &snapshot,
                        statement_digest,
                        block_height: transaction.block_height(),
                        expected_action_index: 0,
                        state_transaction: transaction,
                    },
                    TypedProofManagedNoteApplyV1::IvmPrivateNote {
                        statement: &statement,
                        nullifiers: &statement.nullifiers,
                        output_commitments: &statement.output_commitments,
                        successor_state: &successor,
                    },
                )
                .expect_err("adversarial private-IVM apply must reject");
                assert_eq!(
                    proof_managed_state_snapshot(transaction, config_key),
                    before,
                    "rejected apply mutated roots, heads, nullifiers, commitments, config, or budget: {error:?}"
                );
            };
        let mut wrong_next_root = successor.root().into_bytes();
        wrong_next_root[0] ^= 1;
        assert_atomic_rejection(&effect(PrivacyRootV1::new(wrong_next_root)), &transaction);
        let replay_key = PrivacyNullifierKeyV1::proof_managed_nullifier(
            snapshot.namespace(),
            statement.nullifiers[0],
        )
        .expect("private-IVM replay key");
        transaction.world.privacy_nullifiers.insert(
            replay_key,
            PrivacyStateItemRecordV1::proof_managed_pool_verified_nullifier(
                snapshot.bootstrap_digest(),
                PrivacyStatementDigestV1::new([0xF1; 32]),
                1,
                1,
                1,
                0,
            )
            .expect("private-IVM replay record"),
        );
        assert_atomic_rejection(&effect(successor.root()), &transaction);
        transaction.world.privacy_nullifiers.remove(replay_key);
        let duplicate_output_key = PrivacyCommitmentKeyV1::proof_managed_pool_commitment(
            snapshot.namespace(),
            statement.output_commitments[0],
        )
        .expect("private-IVM duplicate output key");
        transaction.world.privacy_commitments.insert(
            duplicate_output_key,
            PrivacyStateItemRecordV1::proof_managed_pool_verified_commitment(
                snapshot.bootstrap_digest(),
                PrivacyStatementDigestV1::new([0xF2; 32]),
                successor.epoch(),
                0,
                snapshot.output_count(),
                1,
                1,
                1,
                0,
            )
            .expect("private-IVM duplicate output record"),
        );
        assert_atomic_rejection(&effect(successor.root()), &transaction);
        let (pq_statement, pq_witness) = pq_masp_fixture();
        let pq_input_commitment = pq_witness.inputs()[0]
            .commitment_v1(&pq_statement)
            .expect("canonical PQ-MASP input commitment");
        let pq_snapshot = PrivacyProofManagedPoolSnapshotV1::canonical_pq_masp_bootstrap_for_test(
            PrivacyProofManagedPoolBootstrapV1::PqMaspStarkV1(PrivacyPqMaspPoolBootstrapV1 {
                pool_id: pq_statement.pool_id,
                asset_definition_id: pq_statement.asset_definition_id.clone(),
                initial_note_commitments: vec![pq_input_commitment],
            }),
        );
        assert_eq!(pq_statement.anchor, pq_snapshot.current_root());
        assert_eq!(pq_statement.anchor_epoch, pq_snapshot.current_epoch());
        let pq_successor = pq_snapshot
            .derive_note_successor(&pq_statement.output_commitments)
            .expect("PQ-MASP successor");
        let pq_statement_digest = PrivacyStatementV1::PqMaspStarkV1(pq_statement.clone())
            .digest()
            .expect("PQ-MASP statement digest");
        let mut wrong_pq_next_root = pq_successor.root().into_bytes();
        wrong_pq_next_root[0] ^= 1;
        let pq_effect = VerifiedProofManagedPoolLedgerEffectV1::from_test_parts(
            VerifiedProofManagedPoolLedgerEffectTestPartsV1 {
                namespace: pq_snapshot.namespace(),
                bootstrap_digest: pq_snapshot.bootstrap_digest(),
                asset_definition_id: pq_statement.asset_definition_id.clone(),
                current_root: pq_snapshot.current_root(),
                current_epoch: pq_snapshot.current_epoch(),
                next_root: PrivacyRootV1::new(wrong_pq_next_root),
                next_epoch: pq_successor.epoch(),
                transition: VerifiedProofManagedPoolTransitionV1::PqMasp {
                    nullifiers: pq_statement.nullifiers.clone(),
                    output_commitments: pq_statement.output_commitments.clone(),
                    successor_state: pq_successor.clone(),
                },
                value_balance: None,
                public_balance_scope: None,
            },
        );
        let pq_config_key =
            PrivacyCommitmentKeyV1::proof_managed_pool_config(pq_snapshot.namespace())
                .expect("PQ-MASP config key");
        let before = proof_managed_state_snapshot(&transaction, pq_config_key);
        let error = prepare_proof_managed_note_apply_v1(
            ProofManagedNoteApplyContextV1 {
                effect: &pq_effect,
                snapshot: &pq_snapshot,
                statement_digest: pq_statement_digest,
                block_height: transaction.block_height(),
                expected_action_index: 0,
                state_transaction: &transaction,
            },
            TypedProofManagedNoteApplyV1::PqMasp {
                statement: &pq_statement,
                nullifiers: &pq_statement.nullifiers,
                output_commitments: &pq_statement.output_commitments,
                successor_state: &pq_successor,
            },
        )
        .expect_err("adversarial PQ-MASP apply must reject");
        assert_eq!(
            proof_managed_state_snapshot(&transaction, pq_config_key),
            before,
            "rejected PQ-MASP apply mutated roots, heads, nullifiers, commitments, config, or budget: {error:?}"
        );
    }
    #[test]
    fn bootle_lantern_submit_policy_resolution_is_exact_and_fail_closed() {
        let policy = bootle_lantern_policy(1, BootleLanternIssuerPolicyLifecycleV1::Active);
        let statement = bootle_lantern_statement(&policy);
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            policy.issuer_id,
            policy.policy_id,
        )
        .expect("Bootle/Lantern policy key");
        let mut commitments = Storage::<PrivacyCommitmentKeyV1, PrivacyStateItemRecordV1>::new();
        let error = load_active_bootle_lantern_policy_v1(&statement, &commitments.view())
            .expect_err("missing authoritative policy must reject");
        assert!(
            smart_contract_parameter_message(&error).contains("not registered"),
            "{error:?}"
        );
        commitments.insert(
            key,
            PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(policy.clone(), 7)
                .expect("valid governed Bootle/Lantern policy"),
        );
        assert_eq!(
            load_active_bootle_lantern_policy_v1(&statement, &commitments.view())
                .expect("exact active policy"),
            policy
        );
        let statement_mutations: [(&str, fn(&mut IrohaBootleLanternAnoncredStatementV1), &str); 6] = [
            (
                "issuer",
                |statement| statement.issuer_id.0[0] ^= 1,
                "not registered",
            ),
            (
                "policy",
                |statement| statement.policy_id.0[0] ^= 1,
                "not registered",
            ),
            (
                "record digest",
                |statement| statement.issuer_policy_record_digest.0[0] ^= 1,
                "does not exactly match",
            ),
            (
                "epoch",
                |statement| statement.issuer_policy_epoch += 1,
                "does not exactly match",
            ),
            (
                "issuer parameter id",
                |statement| statement.issuer_parameter_id.0[0] ^= 1,
                "does not exactly match",
            ),
            (
                "issuer parameter digest",
                |statement| statement.issuer_parameter_digest.0[0] ^= 1,
                "does not exactly match",
            ),
        ];
        for (label, mutate, expected) in statement_mutations {
            let mut substituted = statement.clone();
            mutate(&mut substituted);
            let error = load_active_bootle_lantern_policy_v1(&substituted, &commitments.view())
                .expect_err("statement substitution must reject");
            assert!(
                smart_contract_parameter_message(&error).contains(expected),
                "{label} substitution returned {error:?}"
            );
        }
        let rotated = rotate_bootle_lantern_policy(&policy);
        commitments.insert(
            key,
            PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(rotated.clone(), 8)
                .expect("valid rotated policy state"),
        );
        let error = load_active_bootle_lantern_policy_v1(&statement, &commitments.view())
            .expect_err("statement selecting a superseded policy revision must reject");
        assert!(
            smart_contract_parameter_message(&error).contains("does not exactly match"),
            "{error:?}"
        );
        let rotated_statement = bootle_lantern_statement(&rotated);
        assert_eq!(
            load_active_bootle_lantern_policy_v1(&rotated_statement, &commitments.view())
                .expect("statement selects current rotated policy"),
            rotated
        );
        let revoked = revoke_bootle_lantern_policy(&rotated);
        let revoked_statement = bootle_lantern_statement(&revoked);
        commitments.insert(
            key,
            PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(revoked, 9)
                .expect("valid terminal policy state"),
        );
        let error = load_active_bootle_lantern_policy_v1(&revoked_statement, &commitments.view())
            .expect_err("revoked policy must reject");
        assert!(
            smart_contract_parameter_message(&error).contains("revoked"),
            "{error:?}"
        );
        let mut corrupted = policy.clone();
        corrupted.record_digest.0[0] ^= 1;
        commitments.insert(
            key,
            PrivacyStateItemRecordV1::BootleLanternIssuerPolicyGovernance {
                policy: corrupted,
                admitted_at_height: 9,
            },
        );
        let error = load_active_bootle_lantern_policy_v1(&statement, &commitments.view())
            .expect_err("corrupted authoritative policy must reject");
        assert!(
            matches!(error, Error::InvariantViolation(_)),
            "corrupted policy returned {error:?}"
        );
        commitments.insert(
            key,
            PrivacyStateItemRecordV1::zk_ace_policy_governance(valid_zk_ace_policy(), 10)
                .expect("valid wrong-role state record"),
        );
        let error = load_active_bootle_lantern_policy_v1(&statement, &commitments.view())
            .expect_err("wrong-role authoritative state must reject");
        assert!(
            matches!(error, Error::InvariantViolation(_)),
            "wrong-role state returned {error:?}"
        );
    }
    #[test]
    fn bootle_lantern_governance_requires_the_exact_registered_activation() {
        let initial = bootle_lantern_policy(1, BootleLanternIssuerPolicyLifecycleV1::Active);
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            initial.issuer_id,
            initial.policy_id,
        )
        .expect("Bootle/Lantern policy key");
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        let budget_before = transaction.privacy_budget_for_testing();
        let error = RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial.clone())
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("an unrelated compiled activation does not register Bootle/Lantern");
        assert!(
            smart_contract_parameter_message(&error).contains("not registered"),
            "{error:?}"
        );
        assert_eq!(transaction.world.privacy_commitments.get(&key), None);
        assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        let unrelated_activation = *transaction
            .world
            .privacy_activations
            .get(&PrivacyActivationKeyV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            ))
            .expect("unrelated compiled activation");
        transaction.world.privacy_activations.insert(
            PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1),
            unrelated_activation,
        );
        let error = RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial)
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("a wrong-role activation under the exact key fails closed");
        assert!(
            matches!(error, Error::InvariantViolation(_)),
            "wrong-role activation returned {error:?}"
        );
        assert!(
            error.to_string().contains("mismatched protocol id"),
            "{error}"
        );
        assert_eq!(transaction.world.privacy_commitments.get(&key), None);
        assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
    }
    #[test]
    fn bootle_lantern_governance_registers_rotates_revokes_and_is_failure_atomic() {
        let state = state_with_exact_bootle_lantern_activation();
        let header = test_header();
        let header_hash = header.hash();
        let mut block = state.block(header);
        let initial = bootle_lantern_policy(1, BootleLanternIssuerPolicyLifecycleV1::Active);
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            initial.issuer_id,
            initial.policy_id,
        )
        .expect("Bootle/Lantern policy key");
        {
            let mut transaction = block.transaction();
            let error = RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("governance permission is mandatory");
            assert!(error.to_string().contains("CanEnactGovernance"), "{error}");
            assert_eq!(transaction.world.privacy_commitments.get(&key), None);
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("empty Bootle/Lantern registry"),
                0
            );
            assert_eq!(transaction.privacy_budget_for_testing(), (0, 0, 0, 0));
        }
        {
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            let instruction = RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial.clone());
            let encoded_instruction_bytes = u64::try_from(
                norito::to_bytes(&instruction)
                    .expect("registration instruction encoding")
                    .len(),
            )
            .expect("registration instruction length fits u64");
            instruction
                .execute(&ALICE_ID, &mut transaction)
                .expect("register exact origin policy");
            assert_eq!(
                transaction.privacy_budget_for_testing().0,
                1,
                "registration reserves one action"
            );
            assert_eq!(
                transaction.privacy_budget_for_testing().1,
                encoded_instruction_bytes,
                "governance preflight accounts for the complete ISI encoding"
            );
            assert_eq!(
                load_privacy_bootle_lantern_issuer_policy_v1(
                    initial.issuer_id,
                    initial.policy_id,
                    &transaction.world.privacy_commitments,
                )
                .expect("registered policy"),
                initial
            );
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            let count_before = privacy_bootle_lantern_issuer_policy_count_v1(
                &transaction.world.privacy_commitments,
            )
            .expect("valid singleton policy registry");
            let budget_before = transaction.privacy_budget_for_testing();
            let error = RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("duplicate registration must reject");
            assert!(
                smart_contract_parameter_message(&error).contains("already registered"),
                "{error:?}"
            );
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("duplicate rejection preserves the registry"),
                count_before
            );
            assert_eq!(
                transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .and_then(PrivacyStateItemRecordV1::bootle_lantern_issuer_policy),
                Some(&initial)
            );
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
        let rotated = rotate_bootle_lantern_policy(&initial);
        {
            let mut transaction = block.transaction();
            RotatePrivacyBootleLanternIssuerPolicyV1::new(initial.record_digest, rotated.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect("rotate exactly one active epoch");
            assert_eq!(
                load_privacy_bootle_lantern_issuer_policy_v1(
                    initial.issuer_id,
                    initial.policy_id,
                    &transaction.world.privacy_commitments,
                )
                .expect("rotated policy"),
                rotated
            );
            transaction.apply();
        }
        block
            .commit_world_overlay_for_testing()
            .expect("commit Bootle/Lantern registration and rotation block");
        let next_header = BlockHeader::new(
            NonZeroU64::new(TEST_BLOCK_HEIGHT + 1).expect("non-zero height"),
            Some(header_hash),
            None,
            1_800_000_000_001,
            0,
        );
        let mut block = state.block(next_header);
        {
            let mut transaction = block.transaction();
            let count_before = privacy_bootle_lantern_issuer_policy_count_v1(
                &transaction.world.privacy_commitments,
            )
            .expect("valid singleton policy registry");
            let budget_before = transaction.privacy_budget_for_testing();
            let stale_successor = rotate_bootle_lantern_policy(&rotated);
            let error = RotatePrivacyBootleLanternIssuerPolicyV1::new(
                initial.record_digest,
                stale_successor,
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("stale compare-and-swap digest must reject");
            assert!(
                smart_contract_parameter_message(&error).contains("stale or substituted"),
                "{error:?}"
            );
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("stale CAS rejection preserves the registry"),
                count_before
            );
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
            assert_eq!(
                transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .and_then(PrivacyStateItemRecordV1::bootle_lantern_issuer_policy),
                Some(&rotated)
            );
        }
        let revoked = revoke_bootle_lantern_policy(&rotated);
        {
            let mut transaction = block.transaction();
            RevokePrivacyBootleLanternIssuerPolicyV1::new(rotated.record_digest, revoked.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect("revoke exactly one epoch without changing policy material");
            assert_eq!(
                load_privacy_bootle_lantern_issuer_policy_v1(
                    initial.issuer_id,
                    initial.policy_id,
                    &transaction.world.privacy_commitments,
                )
                .expect("terminal policy"),
                revoked
            );
            transaction.apply();
        }
        {
            let mut post_terminal = revoked.clone();
            post_terminal.epoch += 1;
            post_terminal.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Active;
            post_terminal.issuer_parameter_id.0[0] ^= 1;
            post_terminal.issuer_parameter_digest = post_terminal
                .computed_issuer_parameter_digest()
                .expect("post-terminal issuer matrix");
            post_terminal.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
            post_terminal.record_digest = post_terminal
                .computed_record_digest()
                .expect("post-terminal policy digest");
            let mut transaction = block.transaction();
            let count_before = privacy_bootle_lantern_issuer_policy_count_v1(
                &transaction.world.privacy_commitments,
            )
            .expect("valid singleton terminal policy registry");
            let budget_before = transaction.privacy_budget_for_testing();
            let error =
                RotatePrivacyBootleLanternIssuerPolicyV1::new(revoked.record_digest, post_terminal)
                    .execute(&ALICE_ID, &mut transaction)
                    .expect_err("revoked lineage is terminal");
            assert_eq!(
                smart_contract_parameter_message(&error),
                "Bootle/Lantern issuer-policy rotation rejected: Bootle/Lantern issuer policy is already terminal-revoked",
                "{error:?}"
            );
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("terminal rejection preserves the registry"),
                count_before
            );
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
            assert_eq!(
                transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .and_then(PrivacyStateItemRecordV1::bootle_lantern_issuer_policy),
                Some(&revoked)
            );
        }
    }
    #[test]
    fn bootle_lantern_governance_rejects_transition_substitution_without_mutation() {
        let state = state_with_exact_bootle_lantern_activation();
        let mut block = state.block(test_header());
        let current = bootle_lantern_policy(1, BootleLanternIssuerPolicyLifecycleV1::Active);
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            current.issuer_id,
            current.policy_id,
        )
        .expect("Bootle/Lantern policy key");
        {
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            RegisterPrivacyBootleLanternIssuerPolicyV1::new(current.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect("register transition-test origin");
            transaction.apply();
        }
        let rotated = rotate_bootle_lantern_policy(&current);
        let mut skipped_epoch = rotated.clone();
        skipped_epoch.epoch += 1;
        skipped_epoch.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        skipped_epoch.record_digest = skipped_epoch
            .computed_record_digest()
            .expect("skipped-epoch policy digest");
        let mut unchanged = current.clone();
        unchanged.epoch += 1;
        unchanged.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        unchanged.record_digest = unchanged
            .computed_record_digest()
            .expect("unchanged policy digest");
        let mut substituted_namespace = rotated.clone();
        substituted_namespace.policy_id.0[0] ^= 1;
        substituted_namespace.record_digest =
            PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        substituted_namespace.record_digest = substituted_namespace
            .computed_record_digest()
            .expect("substituted-namespace policy digest");
        let rotation_cases = [
            (
                "zero compare-and-swap digest",
                RotatePrivacyBootleLanternIssuerPolicyV1::new(
                    PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]),
                    rotated.clone(),
                ),
                "non-zero",
            ),
            (
                "skipped policy epoch",
                RotatePrivacyBootleLanternIssuerPolicyV1::new(current.record_digest, skipped_epoch),
                "advance exactly once",
            ),
            (
                "unchanged policy material",
                RotatePrivacyBootleLanternIssuerPolicyV1::new(current.record_digest, unchanged),
                "change",
            ),
            (
                "substituted policy namespace",
                RotatePrivacyBootleLanternIssuerPolicyV1::new(
                    current.record_digest,
                    substituted_namespace,
                ),
                "not registered",
            ),
        ];
        for (label, instruction, expected_message) in rotation_cases {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let error = instruction
                .execute(&ALICE_ID, &mut transaction)
                .expect_err(label);
            assert!(
                smart_contract_parameter_message(&error).contains(expected_message),
                "{label} returned {error:?}"
            );
            assert_eq!(
                transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .and_then(PrivacyStateItemRecordV1::bootle_lantern_issuer_policy),
                Some(&current),
                "{label} changed the current policy"
            );
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("rejected rotation preserves a valid registry"),
                1,
                "{label} changed the registry count"
            );
            assert_eq!(
                transaction.privacy_budget_for_testing(),
                budget_before,
                "{label} reserved privacy budget"
            );
        }
        let mut mutating_revocation = rotated.clone();
        mutating_revocation.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Revoked;
        mutating_revocation.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        mutating_revocation.record_digest = mutating_revocation
            .computed_record_digest()
            .expect("mutating-revocation policy digest");
        let revocation_cases = [
            (
                "active revocation successor",
                RevokePrivacyBootleLanternIssuerPolicyV1::new(current.record_digest, rotated),
                "revoked",
            ),
            (
                "revocation that rotates issuer material",
                RevokePrivacyBootleLanternIssuerPolicyV1::new(
                    current.record_digest,
                    mutating_revocation,
                ),
                "preserve",
            ),
        ];
        for (label, instruction, expected_message) in revocation_cases {
            let mut transaction = block.transaction();
            let budget_before = transaction.privacy_budget_for_testing();
            let error = instruction
                .execute(&ALICE_ID, &mut transaction)
                .expect_err(label);
            assert!(
                smart_contract_parameter_message(&error).contains(expected_message),
                "{label} returned {error:?}"
            );
            assert_eq!(
                transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .and_then(PrivacyStateItemRecordV1::bootle_lantern_issuer_policy),
                Some(&current),
                "{label} changed the current policy"
            );
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("rejected revocation preserves a valid registry"),
                1,
                "{label} changed the registry count"
            );
            assert_eq!(
                transaction.privacy_budget_for_testing(),
                budget_before,
                "{label} reserved privacy budget"
            );
        }
    }
    #[test]
    fn bootle_lantern_governance_preflight_and_registry_cap_reject_without_mutation() {
        let initial = bootle_lantern_policy(1, BootleLanternIssuerPolicyLifecycleV1::Active);
        let key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
            initial.issuer_id,
            initial.policy_id,
        )
        .expect("Bootle/Lantern policy key");
        let state = state_with_exact_bootle_lantern_activation();
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        transaction
            .reserve_privacy_action(0, 64)
            .expect("consume the sole transaction action");
        let budget_before = transaction.privacy_budget_for_testing();
        let error = RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial.clone())
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("exhausted transaction action budget");
        assert!(
            smart_contract_parameter_message(&error)
                .contains("action count per transaction exceeded"),
            "{error}"
        );
        assert_eq!(transaction.world.privacy_commitments.get(&key), None);
        assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        let state = state_with_exact_bootle_lantern_activation();
        let mut block = state.block(test_header());
        {
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            let template = initial.clone();
            for index in 0..(BOOTLE_LANTERN_MAX_ISSUER_POLICIES_V1 - 1) {
                let mut policy = template.clone();
                let index = u64::try_from(index).expect("policy index fits u64");
                let mut policy_id = [0; 32];
                policy_id[0] = 0xC1;
                policy_id[1..9].copy_from_slice(&index.to_le_bytes());
                policy.policy_id = PrivacyPolicyIdV1::new(policy_id);
                policy.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
                policy.record_digest = policy
                    .computed_record_digest()
                    .expect("bounded policy digest");
                let policy_key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
                    policy.issuer_id,
                    policy.policy_id,
                )
                .expect("bounded policy key");
                let record =
                    PrivacyStateItemRecordV1::bootle_lantern_issuer_policy_governance(policy, 1)
                        .expect("bounded policy record");
                transaction
                    .world
                    .privacy_commitments
                    .insert(policy_key, record);
            }
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("valid registry below the cap"),
                BOOTLE_LANTERN_MAX_ISSUER_POLICIES_V1 - 1
            );
            RegisterPrivacyBootleLanternIssuerPolicyV1::new(initial.clone())
                .execute(&ALICE_ID, &mut transaction)
                .expect("the final policy slot is admissible");
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("valid registry exactly at the cap"),
                BOOTLE_LANTERN_MAX_ISSUER_POLICIES_V1
            );
            assert_eq!(
                transaction
                    .world
                    .privacy_commitments
                    .get(&key)
                    .and_then(PrivacyStateItemRecordV1::bootle_lantern_issuer_policy),
                Some(&initial)
            );
            transaction.apply();
        }
        {
            let mut over_policy = initial;
            over_policy.policy_id = PrivacyPolicyIdV1::new([0xD1; 32]);
            over_policy.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
            over_policy.record_digest = over_policy
                .computed_record_digest()
                .expect("over-cap policy digest");
            let over_key = PrivacyCommitmentKeyV1::bootle_lantern_issuer_policy(
                over_policy.issuer_id,
                over_policy.policy_id,
            )
            .expect("over-cap policy key");
            let mut transaction = block.transaction();
            let count_before = privacy_bootle_lantern_issuer_policy_count_v1(
                &transaction.world.privacy_commitments,
            )
            .expect("valid registry at the cap");
            let budget_before = transaction.privacy_budget_for_testing();
            let error = RegisterPrivacyBootleLanternIssuerPolicyV1::new(over_policy)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("policy registry at cap must reject");
            assert!(
                smart_contract_parameter_message(&error).contains("registry is full"),
                "{error:?}"
            );
            assert_eq!(
                privacy_bootle_lantern_issuer_policy_count_v1(
                    &transaction.world.privacy_commitments,
                )
                .expect("failed registration preserves a valid capped registry"),
                count_before
            );
            assert_eq!(transaction.world.privacy_commitments.get(&over_key), None);
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
    }
    #[test]
    fn vega_governance_is_unavailable_without_a_released_engine() {
        let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(CompiledPrivacyProfileErrorV1::EngineUnavailable { protocol_id })
        );
    }
    #[path = "zk_x509_governance_tests.rs"]
    mod zk_x509_governance_tests;
    #[test]
    fn zk_ace_policy_governance_fails_closed_without_activation() {
        let state = state_without_zk_ace_activation();
        let mut block = state.block(test_header());
        let initial = valid_zk_ace_policy();
        let policy_key =
            PrivacyCommitmentKeyV1::zk_ace_policy(initial.policy_id).expect("policy key");
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        let budget_before = transaction.privacy_budget_for_testing();
        let error = RegisterPrivacyZkAcePolicyV1::new(initial)
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("unavailable ZK-ACE profile must not admit policy state");
        assert!(
            smart_contract_parameter_message(&error).contains("not registered"),
            "{error:?}"
        );
        assert_eq!(transaction.world.privacy_commitments.get(&policy_key), None);
        assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
    }
    #[cfg(feature = "zk-stark")]
    #[test]
    fn zk_ace_submit_has_no_activatable_compiled_profile() {
        let protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(
                crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                    protocol_id,
                }
            )
        );
    }
    #[test]
    #[ignore = "release gate: generates and verifies a full masked ZK-AMS batch proof"]
    fn zk_ams_submit_commits_batch_successor_then_provisions_once() {
        let fixture: ZkAmsRuntimeFixtureForTest = zk_ams_runtime_fixture_for_test();
        let namespace = fixture.bootstrap.namespace();
        let bootstrap_digest = fixture.bootstrap.digest();
        let bootstrap_provenance =
            PrivacyRootProvenanceV1::zk_ams_registry_bootstrap(bootstrap_digest, 2)
                .expect("ZK-AMS bootstrap root provenance");
        let prestate_provenance = PrivacyRootProvenanceV1::zk_ams_registry_successor(
            bootstrap_digest,
            fixture.prestate_statement_digest,
            2,
            0,
            fixture.bootstrap.initial_registry_epoch,
            fixture.bootstrap.initial_registry_root,
        )
        .expect("ZK-AMS prestate successor provenance");
        let prestate_item = PrivacyStateItemRecordV1::zk_ams_verified_proof(
            bootstrap_digest,
            fixture.prestate_statement_digest,
            2,
            0,
        )
        .expect("ZK-AMS prestate item provenance");
        let issuer_record_key = PrivacyCommitmentKeyV1::zk_ams_issuer_policy_record(
            namespace,
            fixture.bootstrap.issuer_policy_record_digest(),
        )
        .expect("ZK-AMS issuer record key");
        let mut world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        world.privacy_activations.insert(
            PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::IrohaZkAmsV1),
            fixture.activation,
        );
        world.privacy_commitments.insert(
            issuer_record_key,
            PrivacyStateItemRecordV1::zk_ams_governance(bootstrap_digest, 2)
                .expect("ZK-AMS issuer governance record"),
        );
        for anchor in &fixture.prestate_anchors {
            world.privacy_commitments.insert(
                PrivacyCommitmentKeyV1::zk_ams_phc(namespace, anchor.phc_hash)
                    .expect("ZK-AMS prestate PHC key"),
                prestate_item.clone(),
            );
            world.privacy_commitments.insert(
                PrivacyCommitmentKeyV1::zk_ams_seed_key(namespace, anchor.seed_public_key)
                    .expect("ZK-AMS prestate seed key"),
                prestate_item.clone(),
            );
        }
        world.privacy_roots.insert(
            PrivacyRootKeyV1::new(
                namespace,
                PrivacyRootRoleV1::AccountRegistry,
                fixture.bootstrap.initial_registry_epoch,
                fixture.bootstrap.initial_registry_root,
            )
            .expect("ZK-AMS bootstrap root key"),
            bootstrap_provenance,
        );
        world.privacy_roots.insert(
            PrivacyRootKeyV1::new(
                namespace,
                PrivacyRootRoleV1::AccountRegistry,
                fixture.current_epoch,
                fixture.current_root,
            )
            .expect("ZK-AMS prestate root key"),
            prestate_provenance,
        );
        let head_key = PrivacyRootHeadKeyV1::new(namespace, PrivacyRootRoleV1::AccountRegistry)
            .expect("ZK-AMS root-head key");
        world.privacy_root_heads.insert(
            head_key,
            PrivacyRootHeadRecordV1::new(
                fixture.current_epoch,
                fixture.current_root,
                prestate_provenance,
                None,
            )
            .expect("ZK-AMS prestate root head"),
        );
        let mut state = State::new_with_chain_and_network_id_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            TEST_CHAIN_ID.into(),
            fixture.network_id,
        );
        install_synthetic_privacy_genesis_hash(&mut state, fixture.genesis_hash);
        let header = BlockHeader::new(
            NonZeroU64::new(fixture.current_height).expect("non-zero ZK-AMS height"),
            None,
            None,
            fixture.block_timestamp_ms,
            0,
        );
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        let batch_instruction = SubmitPrivacyProofV1::new(fixture.batch_envelope.clone());
        bind_submit_privacy_instruction(&mut transaction, &batch_instruction);
        batch_instruction
            .execute(&ALICE_ID, &mut transaction)
            .expect("native ZK-AMS batch state transition");
        let PrivacyStatementV1::IrohaZkAmsV1(batch_statement) = &fixture.batch_envelope.statement
        else {
            unreachable!("ZK-AMS batch fixture")
        };
        let PrivacyZkAmsActionV1::BatchAdmission(batch) = &batch_statement.action else {
            unreachable!("ZK-AMS batch action")
        };
        // ZK-AMS v1 binds every proof to the sole action index zero, so the
        // ordered batch and provisioning actions belong to distinct transactions.
        let head_after_batch = transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .copied()
            .expect("ZK-AMS successor root head");
        assert_eq!(
            (head_after_batch.epoch(), head_after_batch.root()),
            (
                batch.next_account_registry_root_epoch,
                batch.next_account_registry_root
            )
        );
        for anchor in &batch.anchors {
            assert!(
                transaction
                    .world
                    .privacy_commitments
                    .get(
                        &PrivacyCommitmentKeyV1::zk_ams_seed_key(
                            namespace,
                            anchor.seed_public_key,
                        )
                        .expect("admitted ZK-AMS seed key")
                    )
                    .is_some()
            );
        }
        transaction.apply();
        let provision_instruction = SubmitPrivacyProofV1::new(fixture.provision_envelope.clone());
        let PrivacyStatementV1::IrohaZkAmsV1(provision_statement) =
            &fixture.provision_envelope.statement
        else {
            unreachable!("ZK-AMS provision fixture")
        };
        let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &provision_statement.action else {
            unreachable!("ZK-AMS provision action")
        };
        let key_image_key = PrivacyNullifierKeyV1::zk_ams_key_image(namespace, provision.key_image)
            .expect("ZK-AMS key-image key");
        let mut transaction = block.transaction();
        let committed_head = transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .copied()
            .expect("committed ZK-AMS successor root head");
        assert_eq!(
            (committed_head.epoch(), committed_head.root()),
            (
                provision.account_registry_root_epoch,
                provision.account_registry_root
            ),
            "provisioning transaction must inherit the admitted batch successor"
        );
        bind_submit_privacy_instruction(&mut transaction, &provision_instruction);
        provision_instruction
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect("native ZK-AMS provisioning transition");
        assert!(
            transaction
                .world
                .accounts
                .get(&provision.account_id)
                .is_some(),
            "ZK-AMS provisioning must create the proof-bound account"
        );
        assert!(
            transaction
                .world
                .privacy_nullifiers
                .get(&key_image_key)
                .is_some(),
            "ZK-AMS provisioning must persist the replay key image"
        );
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit ZK-AMS batch and provisioning transactions");
        let replay_height = fixture
            .current_height
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .expect("next non-zero ZK-AMS height");
        let replay_timestamp_ms = fixture
            .block_timestamp_ms
            .checked_add(1)
            .expect("next ZK-AMS block timestamp");
        let replay_header = BlockHeader::new(replay_height, None, None, replay_timestamp_ms, 0);
        let mut replay_block = state.block(replay_header);
        let mut transaction = replay_block.transaction();
        assert!(
            transaction
                .world
                .accounts
                .get(&provision.account_id)
                .is_some(),
            "ZK-AMS provisioning account must survive the block commit"
        );
        let budget_before_replay = transaction.privacy_budget_for_testing();
        let account_count_before_replay = transaction.world.accounts.iter().count();
        let key_image_before_replay = transaction
            .world
            .privacy_nullifiers
            .get(&key_image_key)
            .cloned()
            .expect("committed ZK-AMS replay key image");
        let head_before_replay = transaction
            .world
            .privacy_root_heads
            .get(&head_key)
            .copied()
            .expect("committed ZK-AMS registry head");
        bind_submit_privacy_instruction(&mut transaction, &provision_instruction);
        let replay_error = provision_instruction
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("ZK-AMS key-image replay must reject");
        assert!(
            smart_contract_parameter_message(&replay_error).contains("already consumed"),
            "{replay_error:?}"
        );
        assert_eq!(
            transaction.privacy_budget_for_testing(),
            budget_before_replay,
            "ZK-AMS replay rejection must not reserve budget"
        );
        assert_eq!(
            transaction.world.accounts.iter().count(),
            account_count_before_replay,
            "ZK-AMS replay rejection must not create another account"
        );
        assert_eq!(
            transaction.world.privacy_nullifiers.get(&key_image_key),
            Some(&key_image_before_replay),
            "ZK-AMS replay rejection must preserve key-image provenance"
        );
        assert_eq!(
            transaction.world.privacy_root_heads.get(&head_key).copied(),
            Some(head_before_replay),
            "ZK-AMS replay rejection must preserve the registry head"
        );
    }
    #[test]
    fn zk_ace_policy_governance_has_no_compiled_activation_to_substitute() {
        let protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
        assert_eq!(
            compiled_privacy_profile_v1(protocol_id),
            Err(
                crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                    protocol_id,
                }
            )
        );
        let state = state_without_zk_ace_activation();
        let mut block = state.block(test_header());
        let transaction = block.transaction();
        assert!(
            transaction
                .world
                .privacy_activations
                .get(&PrivacyActivationKeyV1::new(protocol_id))
                .is_none()
        );
    }
    #[test]
    fn consensus_policy_schedule_rejects_bad_authority_timing_limits_and_overwrite() {
        let mut next_limits = PrivacyConsensusLimitsV1::taira_default();
        next_limits.max_actions_per_block -= 1;
        next_limits.retained_root_count -= 1;
        let valid =
            SchedulePrivacyConsensusPolicyTighteningV1::new(TEST_BLOCK_HEIGHT + 1, next_limits);
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        let original = *transaction.world.privacy_consensus_policy.get();
        let error = valid
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("governance permission is mandatory");
        assert!(error.to_string().contains("CanEnactGovernance"), "{error}");
        assert_eq!(*transaction.world.privacy_consensus_policy.get(), original);
        grant_governance(&mut transaction);
        for invalid in [
            SchedulePrivacyConsensusPolicyTighteningV1::new(1, next_limits),
            SchedulePrivacyConsensusPolicyTighteningV1::new(TEST_BLOCK_HEIGHT, next_limits),
            SchedulePrivacyConsensusPolicyTighteningV1::new(0, next_limits),
            SchedulePrivacyConsensusPolicyTighteningV1::new(
                TEST_BLOCK_HEIGHT + 1,
                PrivacyConsensusLimitsV1::taira_default(),
            ),
            {
                let mut increased = next_limits;
                increased.max_actions_per_block =
                    PrivacyConsensusLimitsV1::taira_default().max_actions_per_block + 1;
                SchedulePrivacyConsensusPolicyTighteningV1::new(TEST_BLOCK_HEIGHT + 1, increased)
            },
        ] {
            invalid
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("malformed or non-tightening schedule");
            assert_eq!(
                *transaction.world.privacy_consensus_policy.get(),
                original,
                "rejected scheduling must be read-only"
            );
        }
        valid
            .execute(&ALICE_ID, &mut transaction)
            .expect("next-block strict tightening");
        let scheduled = *transaction.world.privacy_consensus_policy.get();
        assert_eq!(scheduled.current_limits, original.current_limits);
        let pending = scheduled.pending_tightening.expect("pending tightening");
        assert_eq!(pending.scheduled_at_height, TEST_BLOCK_HEIGHT);
        assert_eq!(pending.effective_at_height, TEST_BLOCK_HEIGHT + 1);
        assert_eq!(pending.next_limits, next_limits);
        let mut other_limits = next_limits;
        other_limits.retained_root_count -= 1;
        let error =
            SchedulePrivacyConsensusPolicyTighteningV1::new(TEST_BLOCK_HEIGHT + 2, other_limits)
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("a pending schedule cannot be overwritten");
        assert!(
            smart_contract_parameter_message(&error).contains("already has a pending"),
            "{error}"
        );
        assert_eq!(
            *transaction.world.privacy_consensus_policy.get(),
            scheduled,
            "overwrite rejection must preserve the first schedule byte-for-byte"
        );
    }
    #[test]
    fn protocol_limit_schedule_rejects_bad_authority_mismatch_increase_noop_and_overwrite() {
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        let key = PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1);
        let mut current = *transaction
            .world
            .privacy_activations
            .get(&key)
            .expect("Anonymous PGC activation");
        current.protocol_limits = PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
            AnonymousPgcActivationLimitsV1 {
                max_anonymity_set_size: 32,
                max_recipient_count: 8,
            },
        );
        transaction.world.privacy_activations.insert(key, current);
        let next = PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
            AnonymousPgcActivationLimitsV1 {
                max_anonymity_set_size: 16,
                max_recipient_count: 8,
            },
        );
        let valid = SchedulePrivacyProtocolLimitsTighteningV1::new(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            TEST_BLOCK_HEIGHT + 1,
            next,
        );
        let error = valid
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("governance permission is mandatory");
        assert!(error.to_string().contains("CanEnactGovernance"), "{error}");
        assert_eq!(
            transaction.world.privacy_activations.get(&key),
            Some(&current)
        );
        grant_governance(&mut transaction);
        let invalid = [
            SchedulePrivacyProtocolLimitsTighteningV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                TEST_BLOCK_HEIGHT - 1,
                next,
            ),
            SchedulePrivacyProtocolLimitsTighteningV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                TEST_BLOCK_HEIGHT + 1,
                current.protocol_limits,
            ),
            SchedulePrivacyProtocolLimitsTighteningV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                TEST_BLOCK_HEIGHT + 1,
                PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(
                    AnonymousPgcActivationLimitsV1 {
                        max_anonymity_set_size: 64,
                        max_recipient_count: 8,
                    },
                ),
            ),
            SchedulePrivacyProtocolLimitsTighteningV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                TEST_BLOCK_HEIGHT + 1,
                PrivacyProtocolActivationLimitsV1::VeRangeTransparentRangeV1(
                    iroha_data_model::privacy::VeRangeActivationLimitsV1 {
                        max_aggregation_count: 8,
                    },
                ),
            ),
            SchedulePrivacyProtocolLimitsTighteningV1::new(
                PrivacyProtocolIdV1::PqMaspStarkV1,
                TEST_BLOCK_HEIGHT + 1,
                PrivacyProtocolActivationLimitsV1::PqMaspStarkV1(
                    iroha_data_model::privacy::PqMaspActivationLimitsV1 {
                        max_input_count: 1,
                        max_output_count: 1,
                    },
                ),
            ),
        ];
        for instruction in invalid {
            instruction
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("invalid protocol schedule");
            assert_eq!(
                transaction.world.privacy_activations.get(&key),
                Some(&current),
                "rejected scheduling must preserve the activation"
            );
        }
        valid
            .execute(&ALICE_ID, &mut transaction)
            .expect("next-block strict protocol tightening");
        let scheduled = *transaction
            .world
            .privacy_activations
            .get(&key)
            .expect("scheduled activation");
        assert_eq!(scheduled.protocol_limits, current.protocol_limits);
        let pending = scheduled
            .pending_protocol_limits_tightening
            .expect("pending protocol limits");
        assert_eq!(pending.scheduled_at_height, TEST_BLOCK_HEIGHT);
        assert_eq!(pending.effective_at_height, TEST_BLOCK_HEIGHT + 1);
        assert_eq!(pending.next_limits, next);
        let error = SchedulePrivacyProtocolLimitsTighteningV1::new(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            TEST_BLOCK_HEIGHT + 2,
            next,
        )
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("a pending protocol schedule cannot be overwritten");
        assert!(
            smart_contract_parameter_message(&error).contains("already has a pending"),
            "{error}"
        );
        assert_eq!(
            transaction.world.privacy_activations.get(&key),
            Some(&scheduled)
        );
    }
    #[test]
    fn next_block_tightening_applies_only_after_committed_schedule() {
        for commit_schedule in [false, true] {
            let state = state_with_activation(active_lifecycle());
            let key = PrivacyActivationKeyV1::new(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1);
            let mut block = state.block(test_header());
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            let original_policy = *transaction.world.privacy_consensus_policy.get();
            let original_activation = *transaction.world.privacy_activations.get(&key).unwrap();
            let mut next_policy = original_policy.current_limits;
            next_policy.retained_root_count -= 1;
            let mut next_protocol = original_activation.protocol_limits;
            let PrivacyProtocolActivationLimitsV1::AnonymousPgcKOutOfNV1(ref mut limits) =
                next_protocol
            else {
                unreachable!("Anonymous PGC fixture")
            };
            limits.max_anonymity_set_size /= 2;
            SchedulePrivacyConsensusPolicyTighteningV1::new(TEST_BLOCK_HEIGHT + 1, next_policy)
                .execute(&ALICE_ID, &mut transaction)
                .expect("governed next-block consensus tightening");
            SchedulePrivacyProtocolLimitsTighteningV1::new(
                PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
                TEST_BLOCK_HEIGHT + 1,
                next_protocol,
            )
            .execute(&ALICE_ID, &mut transaction)
            .expect("governed next-block protocol tightening");
            let pending_policy = transaction.world.privacy_consensus_policy.get();
            assert_eq!(
                pending_policy.current_limits,
                original_policy.current_limits
            );
            assert_eq!(
                pending_policy.admission_retained_root_count(),
                next_policy.retained_root_count
            );
            assert_eq!(
                transaction
                    .world
                    .privacy_activations
                    .get(&key)
                    .unwrap()
                    .protocol_limits,
                original_activation.protocol_limits
            );
            if commit_schedule {
                transaction.apply();
            } else {
                drop(transaction);
            }
            block
                .commit_world_overlay_for_testing()
                .expect("commit admitting block overlay");
            let mut next_block = state.block(test_header_at(TEST_BLOCK_HEIGHT + 1));
            let transaction = next_block.transaction();
            let policy = transaction.world.privacy_consensus_policy.get();
            let activation = transaction.world.privacy_activations.get(&key).unwrap();
            assert_eq!(policy.pending_tightening, None);
            assert_eq!(activation.pending_protocol_limits_tightening, None);
            assert_eq!(activation.lifecycle, original_activation.lifecycle);
            assert_eq!(
                policy.current_limits,
                if commit_schedule {
                    next_policy
                } else {
                    original_policy.current_limits
                }
            );
            assert_eq!(
                activation.protocol_limits,
                if commit_schedule {
                    next_protocol
                } else {
                    original_activation.protocol_limits
                }
            );
        }
    }
    #[test]
    fn pgc_bootstrap_rejects_authority_inactive_and_future_activation_without_mutation() {
        let instruction = valid_bootstrap_instruction();
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        let error = instruction
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("authority without exact governance permission");
        assert!(error.to_string().contains("CanEnactGovernance"), "{error}");
        assert_empty_and_unbudgeted(&transaction);
        for lifecycle in [
            PrivacyProtocolLifecycleV1::Proposed(PrivacyProposedLifecycleV1 {
                proposed_at_height: 1,
            }),
            PrivacyProtocolLifecycleV1::Active(PrivacyActiveLifecycleV1 {
                proposed_at_height: 1,
                activated_at_height: 20,
                state_since_height: 20,
            }),
        ] {
            let state = state_with_activation(lifecycle);
            let mut block = state.block(test_header());
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            let error = instruction
                .clone()
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("inactive or future activation");
            assert!(
                smart_contract_parameter_message(&error).contains("before")
                    || smart_contract_parameter_message(&error).contains("not effective"),
                "{error}"
            );
            assert_empty_and_unbudgeted(&transaction);
        }
    }
    #[test]
    fn pgc_bootstrap_cap_and_action_budget_rejections_are_non_mutating() {
        let mut oversized = valid_bootstrap_instruction();
        oversized.proof = PrivacyPgcBootstrapProofBytesV1::new(vec![
            1;
            usize::try_from(
                TAIRA_PRIVACY_MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1
            )
            .expect("proof cap fits usize")
                + 1
        ]);
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        let error = oversized
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("oversized bootstrap proof");
        assert!(
            smart_contract_parameter_message(&error).contains("exceeding maximum"),
            "{error:?}"
        );
        assert_empty_and_unbudgeted(&transaction);
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        transaction
            .reserve_privacy_action(0, 64)
            .expect("consume the sole transaction action");
        let budget_before = transaction.privacy_budget_for_testing();
        let error = valid_bootstrap_instruction()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("exhausted action budget");
        assert!(
            smart_contract_parameter_message(&error)
                .contains("action count per transaction exceeded"),
            "{error}"
        );
        assert_eq!(privacy_map_counts(&transaction), (0, 0, 0, 0));
        assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
    }
    #[test]
    fn altered_pgc_bootstrap_fields_and_proof_leave_all_state_unchanged() {
        let mut altered_root = valid_bootstrap_instruction();
        altered_root.bootstrap.initial_root = PrivacyRootV1::new([0xD1; 32]);
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        let error = altered_root
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("altered public bootstrap root");
        assert!(
            smart_contract_parameter_message(&error).contains("root does not match"),
            "{error:?}"
        );
        assert_empty_and_unbudgeted(&transaction);
        let mut altered_supply = valid_bootstrap_instruction();
        altered_supply.bootstrap.total_supply += 1;
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        let error = altered_supply
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("altered public aggregate supply");
        assert!(
            smart_contract_parameter_message(&error).contains("root does not match"),
            "{error:?}"
        );
        assert_empty_and_unbudgeted(&transaction);
        let mut altered_proof = valid_bootstrap_instruction();
        let middle = altered_proof.proof.bytes.len() / 2;
        altered_proof.proof.bytes[middle] ^= 1;
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        let error = altered_proof
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("altered native proof");
        assert!(
            smart_contract_parameter_message(&error).contains("proof verification failed"),
            "{error}"
        );
        assert_empty_and_unbudgeted(&transaction);
    }
    #[test]
    fn pgc_bootstrap_rejects_each_preexisting_orphan_without_new_mutation() {
        #[derive(Clone, Copy, Debug)]
        enum Orphan {
            Invariant,
            Account,
            Root,
            Head,
        }
        let instruction = valid_bootstrap_instruction();
        let bootstrap_digest = instruction.bootstrap.digest().expect("bootstrap digest");
        let proof_digest = instruction.proof.digest().expect("proof digest");
        let root_provenance =
            PrivacyRootProvenanceV1::verified_bootstrap(bootstrap_digest, proof_digest, 9)
                .expect("root provenance");
        let account_provenance =
            PrivacyPgcAccountProvenanceV1::bootstrap(bootstrap_digest, proof_digest, 9)
                .expect("account provenance");
        let invariant_key = PrivacyPgcPoolInvariantKeyV1::new(instruction.bootstrap.namespace)
            .expect("invariant key");
        let invariant = PrivacyPgcPoolInvariantV1::new(
            instruction.bootstrap.total_supply,
            instruction.bootstrap.initial_root,
            bootstrap_digest,
            proof_digest,
        )
        .expect("invariant");
        let first_account = &instruction.bootstrap.accounts[0];
        let account_key =
            PrivacyPgcAccountKeyV1::new(instruction.bootstrap.namespace, first_account.public_key)
                .expect("account key");
        let account_state = PrivacyPgcAccountStateV1::new(
            first_account.encrypted_balance,
            instruction.bootstrap.initial_epoch,
            account_provenance,
        )
        .expect("account state");
        let root_key = PrivacyRootKeyV1::new(
            instruction.bootstrap.namespace,
            PrivacyRootRoleV1::PgcAccountState,
            instruction.bootstrap.initial_epoch,
            instruction.bootstrap.initial_root,
        )
        .expect("root key");
        let head_key = PrivacyRootHeadKeyV1::new(
            instruction.bootstrap.namespace,
            PrivacyRootRoleV1::PgcAccountState,
        )
        .expect("head key");
        let head = PrivacyRootHeadRecordV1::new(
            instruction.bootstrap.initial_epoch,
            instruction.bootstrap.initial_root,
            root_provenance,
            None,
        )
        .expect("root head");
        for orphan in [
            Orphan::Invariant,
            Orphan::Account,
            Orphan::Root,
            Orphan::Head,
        ] {
            let state = state_with_activation(active_lifecycle());
            let mut block = state.block(test_header());
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            match orphan {
                Orphan::Invariant => {
                    transaction
                        .world
                        .privacy_pgc_pool_invariants
                        .insert(invariant_key, invariant);
                }
                Orphan::Account => {
                    transaction
                        .world
                        .privacy_pgc_accounts
                        .insert(account_key, account_state);
                }
                Orphan::Root => {
                    transaction
                        .world
                        .privacy_roots
                        .insert(root_key, root_provenance);
                }
                Orphan::Head => {
                    transaction.world.privacy_root_heads.insert(head_key, head);
                }
            }
            let counts_before = privacy_map_counts(&transaction);
            let budget_before = transaction.privacy_budget_for_testing();
            assert!(
                valid_bootstrap_instruction()
                    .execute(&ALICE_ID, &mut transaction)
                    .is_err(),
                "{orphan:?} must reject"
            );
            assert_eq!(
                privacy_map_counts(&transaction),
                counts_before,
                "{orphan:?}: rejection added privacy state"
            );
            assert_eq!(
                transaction.privacy_budget_for_testing(),
                budget_before,
                "{orphan:?}: rejection consumed privacy budget"
            );
        }
    }
    #[test]
    fn successful_pgc_bootstrap_is_atomic_and_double_bootstrap_rejects() {
        let instruction = valid_bootstrap_instruction();
        let encoded_action_bytes = u64::try_from(
            norito::to_bytes(&instruction)
                .expect("instruction encoding")
                .len(),
        )
        .expect("encoded length");
        let state = state_with_activation(active_lifecycle());
        let mut block = state.block(test_header());
        {
            let mut transaction = block.transaction();
            grant_governance(&mut transaction);
            instruction
                .clone()
                .execute(&ALICE_ID, &mut transaction)
                .expect("complete native bootstrap");
            assert_eq!(privacy_map_counts(&transaction), (1, 16, 1, 1));
            assert_eq!(
                transaction.privacy_budget_for_testing(),
                (1, encoded_action_bytes, 1, encoded_action_bytes)
            );
            transaction.apply();
        }
        {
            let mut transaction = block.transaction();
            let counts_before = privacy_map_counts(&transaction);
            let budget_before = transaction.privacy_budget_for_testing();
            let error = instruction
                .execute(&ALICE_ID, &mut transaction)
                .expect_err("double bootstrap");
            assert!(
                smart_contract_parameter_message(&error).contains("already initialized"),
                "{error:?}"
            );
            assert_eq!(privacy_map_counts(&transaction), counts_before);
            assert_eq!(transaction.privacy_budget_for_testing(), budget_before);
        }
    }
    include!("privacy_pgc_payment_tests.rs");
}
