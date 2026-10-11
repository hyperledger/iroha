//! Original generated authority and signed-genesis identity; no response-selected trust roots.

use super::*;
use crate::managed::service_authority::CheckpointImports;
use iroha_crypto::KeyPair;
use iroha_data_model::account::address::ChainDiscriminantGuard;
use sorafs_manifest::signer::protocol::{SignerPurposeBindingV1, SignerRoleV1};

impl ManagedStreamTokenCustody {
    pub(super) fn validate_policy(&self, policy: &SignerCustodyPolicyV1) -> Result<()> {
        encode(policy, 16 * 1024)?;
        policy
            .validate()
            .map_err(|_| invalid("invalid managed custody policy"))?;
        if policy.binding.chain_id != self.authority.config.chain.to_string()
            || policy.binding.network_id != *self.authority.config.network_id.as_bytes()
            || policy.binding.role != SignerRoleV1::StreamToken
            || policy.binding.purpose
                != (SignerPurposeBindingV1::StreamToken {
                    provider_id: *self.authority.provider_id()?.as_bytes(),
                })
            || self
                .authority
                .provider_role(StreamTokenAuthorityRole::TokenSigner)?
                .try_signatory()
                != Some(&policy.binding.public_key)
            || self
                .authority
                .provider_role(StreamTokenAuthorityRole::CustodyAttester)?
                .try_signatory()
                != Some(&policy.attester_public_key)
            || policy.binding.public_key == *self.authority.config.key_pair.public_key()
            || policy.attester_public_key == *self.authority.config.key_pair.public_key()
            || policy.binding.key_revision != 1
            || policy.binding.policy_revision != 1
            || policy.attester_authority.key_revision != 1
            || policy.attester_authority.policy_revision != 1
        {
            return Err(invalid(
                "initial custody policy differs from independent generated roles",
            ));
        }
        Ok(())
    }
    pub(super) fn validate_original(
        &self,
        original: &Original,
        purpose: CustodyPurpose,
    ) -> Result<()> {
        self.validate_original_with_imports(
            original,
            purpose,
            &mut CheckpointImports::new(&self.authority, None),
        )
    }

    pub(super) fn validate_original_with_imports(
        &self,
        original: &Original,
        purpose: CustodyPurpose,
        imports: &mut CheckpointImports<'_, '_>,
    ) -> Result<()> {
        self.validate_original_using_plan(original, purpose, imports, None)
    }

    pub(super) fn validate_original_in_body_read(
        &self,
        original: &Original,
        purpose: CustodyPurpose,
        imports: &mut CheckpointImports<'_, '_>,
        plan: &body_history::BodyOriginalPlan<'_>,
    ) -> Result<()> {
        self.validate_original_using_plan(original, purpose, imports, Some(plan))
    }

    fn validate_original_using_plan(
        &self,
        original: &Original,
        purpose: CustodyPurpose,
        imports: &mut CheckpointImports<'_, '_>,
        plan: Option<&body_history::BodyOriginalPlan<'_>>,
    ) -> Result<()> {
        purpose.directory_name()?;
        if matches!(original.action, Action::Configure(_)) != (purpose == CustodyPurpose::Configure)
        {
            return Err(invalid("retained custody purpose differs"));
        }
        original.validate()?;
        let verifier = imports.decode(&original.checkpoint)?;
        verifier
            .verified_tip_ref()
            .map_err(|_| invalid("invalid original custody checkpoint"))?
            .verify_global_scope(
                self.authority.config.network_id,
                &self.authority.config.chain.to_string(),
            )
            .map_err(|_| invalid("original custody checkpoint is not the selected Global root"))?;
        if original.selection.provider_id != self.authority.provider_id()? {
            return Err(invalid("original custody provider differs"));
        }
        self.validate_original_action(original, purpose, &verifier, plan)
    }
    // Action-owned decodes run only after the original checkpoint and Global root checks.
    // This boundary keeps later enrollment scratch out of the cold native import caller.
    #[inline(never)]
    fn validate_original_action(
        &self,
        original: &Original,
        purpose: CustodyPurpose,
        verifier: &FinalityVerifier,
        plan: Option<&body_history::BodyOriginalPlan<'_>>,
    ) -> Result<()> {
        match &original.action {
            Action::Configure(policy) => {
                self.validate_policy(policy)?;
                if original.selection.current.is_some()
                    || original.selection.expected_revision != 0
                    || original.selection.expected_digest != [0; 32]
                    || original.selection.binding != policy.binding
                {
                    return Err(invalid(
                        "initial custody configuration has a substituted predecessor",
                    ));
                }
            }
            Action::Enroll {
                enrollment, anchor, ..
            } => {
                let current = original
                    .selection
                    .current
                    .as_ref()
                    .ok_or_else(|| invalid("enrollment lacks configured predecessor"))?;
                let control: sorafs_manifest::signer::custody_control::SignerCustodyControlStateV1 =
                    norito::decode_canonical_with_limits(
                        &current.control_state,
                        norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 1024 * 1024, 32),
                    )
                    .map_err(|_| invalid("invalid original governed custody control"))?;
                self.validate_policy(&control.policy)?;
                if control.policy.binding != original.selection.binding
                    || original.selection.expected_revision != current.revision
                    || current
                        .canonical_digest()
                        .map_err(|_| invalid("invalid original custody digest"))?
                        != original.selection.expected_digest
                    || anchor.state_digest != original.selection.expected_digest
                    || anchor.height != verifier.checkpoint().height()
                    || anchor.block_hash
                        != *verifier.checkpoint().tip().block_header.hash().as_ref()
                    || enrollment.len() > 16 * 1024
                {
                    return Err(invalid(
                        "original enrollment differs from its exact native anchor",
                    ));
                }
                let statement: SignerCustodyRecordV1 = norito::decode_canonical_with_limits(
                    enrollment,
                    norito::DecodeLimits::new(4096, 16 * 1024, 16 * 1024, 1024 * 1024, 32),
                )
                .map_err(|_| invalid("invalid retained enrollment statement"))?;
                match purpose {
                    CustodyPurpose::InitialEnroll => {
                        if current.revision != 1
                            || control.active_head.is_some()
                            || current.active_enrollment.is_some()
                            || control.next_sequence != 1
                            || statement.statement.sequence != 1
                        {
                            return Err(invalid(
                                "initial enrollment has a substituted predecessor",
                            ));
                        }
                    }
                    CustodyPurpose::Renewal(sequence) => {
                        // Keep plan acquisition at its original late semantic boundary.
                        // Foreign owners and active admission use the ordinary full producer.
                        match plan.and_then(|plan| plan.for_owner(self)) {
                            Some(plan) => self.validate_renewal_original(
                                original,
                                &control,
                                sequence,
                                || Ok(plan),
                            )?,
                            None => self.validate_renewal_original(
                                original,
                                &control,
                                sequence,
                                || self.authority.provider_plan(),
                            )?,
                        }
                    }
                    CustodyPurpose::Configure => {
                        return Err(invalid("retained custody purpose differs"));
                    }
                }
                if statement.statement.evidence_digest
                    != self.evidence_digest(
                        &control.policy,
                        &original.selection,
                        &original.checkpoint,
                    )?
                {
                    return Err(invalid(
                        "original enrollment evidence differs from authenticated inputs",
                    ));
                }
            }
        }
        Ok(())
    }
    pub(super) fn selection(
        &self,
        binding: &SignerCustodyBindingV1,
        state: &VerifiedStreamTokenCustodyStateV1,
    ) -> Result<StreamTokenCustodySelection> {
        if state.network_id() != self.authority.config.network_id
            || state.provider_id() != self.authority.provider_id()?
            || state.owner()
                != self
                    .authority
                    .provider_role(StreamTokenAuthorityRole::IssuerOperator)?
        {
            return Err(invalid(
                "verified custody state differs from independently selected owner",
            ));
        }
        Ok(StreamTokenCustodySelection {
            provider_id: self.authority.provider_id()?,
            binding: binding.clone(),
            expected_revision: state
                .current()
                .map_or(0, |current| current.record().revision),
            expected_digest: state
                .current()
                .map_or([0; 32], |current| current.anchor().state_digest),
            current: state.current().map(|current| current.record().clone()),
        })
    }
    pub(super) fn attester(&self) -> Result<KeyPair> {
        self.authority
            .validate_profile()
            .map_err(|_| invalid("invalid original custody-attester profile"))?;
        crate::localnet::service_authorities::custody_attester_key(
            &self.authority.prepared,
            &self.authority.manifest,
            self.authority.provider_id()?,
        )
    }
    pub(super) fn evidence_digest(
        &self,
        policy: &SignerCustodyPolicyV1,
        selection: &StreamTokenCustodySelection,
        checkpoint: &[u8],
    ) -> Result<[u8; 32]> {
        let _profile =
            ChainDiscriminantGuard::enter(self.authority.config.account_chain_discriminant);
        let profile = norito::json::to_vec(&self.authority.manifest)
            .map_err(|_| invalid("cannot encode original authority profile"))?;
        let policy = encode(policy, 16 * 1024)?;
        let selection = encode(selection, 64 * 1024)?;
        Ok(*Hash::new_from_chunks(&[
            b"iroha:managed-stream-token-custody-evidence:v1\0",
            self.authority.genesis.genesis.hash().as_ref(),
            &profile,
            &policy,
            &selection,
            Hash::new(checkpoint).as_ref(),
        ])
        .as_ref())
    }
}
