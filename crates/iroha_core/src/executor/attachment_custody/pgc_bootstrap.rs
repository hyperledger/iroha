//! Consume an original signed attachment with the existing native PGC relation.
//!
//! This is a Core-internal component, not a native admission route. It does not
//! establish governance permission, committed lifecycle/State freshness, a VM
//! execution result, a budget reservation or an authoritative receipt. The
//! caller owns those checks and must supply the actual authorized invocation
//! and trusted network/profile. Success grants no reusable verification token.
//!
//! TODO(I.3, I.4): qualify the direct State route and integrate the actual ABI
//! queue before opening their admission predicates. The request carries only
//! its canonical action/slot reference; no embedded-proof fallback exists.

use super::{ActionRequest, AttachmentHandle, CustodyError, Invocation, InvocationGuard};
use crate::{
    privacy_engines::anonymous_pgc::{
        AnonymousPgcError, AnonymousPgcParametersV1, AnonymousPgcReadError,
        TwistedElGamalCiphertextV1, TwistedElGamalPublicKeyV1,
        bootstrap::{AnonymousPgcBootstrapStatementV1, verify_bootstrap_encoded},
    },
    privacy_engines::p256::TranscriptBindingV1,
    privacy_profiles::{
        CompiledPrivacyProfileValidationErrorV1, validate_compiled_privacy_activation_v1,
    },
    privacy_state::{PrivacyPgcAccountStateRootErrorV1, derive_privacy_pgc_account_state_root_v1},
};
use iroha_data_model::{
    NetworkId,
    isi::privacy::BootstrapPrivacyPgcAccountsV1,
    privacy::{
        PrivacyPgcAccountBootstrapV1, PrivacyPgcAccountBootstrapValidationError,
        PrivacyPgcBootstrapProofBytesV1, PrivacyPgcBootstrapProofDigestV1,
        PrivacyPgcBootstrapProofValidationError, PrivacyProtocolActivationRecordV1,
        PrivacyProtocolIdV1,
    },
    transaction::signed_attachments::{
        ActionOperationV1, ActionPublicInputsDigestV1, ActionRoleV1, AttachmentKindV1,
        AttachmentRoleV1,
    },
};

/// Native relation input supplied by the trusted runtime owner, never the guest.
/// This borrowed record is not evidence of active lifecycle or authorization.
#[derive(Clone, Copy)]
pub(crate) struct BootstrapContext<'a> {
    /// The actual runtime network identity.
    pub(crate) network_id: &'a NetworkId,
    /// The actual committed genesis hash.
    pub(crate) genesis_hash: [u8; 32],
    /// The selected committed activation's cryptographic bindings.
    pub(crate) activation: &'a PrivacyProtocolActivationRecordV1,
}

/// Original typed causes of this bounded consumer; none is a State verdict.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BootstrapError {
    /// Invocation, signature or signed-declaration refusal.
    #[error(transparent)]
    Custody(#[from] CustodyError),
    /// Malformed public bootstrap table.
    #[error(transparent)]
    Bootstrap(#[from] PrivacyPgcAccountBootstrapValidationError),
    /// Canonical account-root derivation failed.
    #[error(transparent)]
    Root(#[from] PrivacyPgcAccountStateRootErrorV1),
    /// The supplied profile does not match the compiled native owner.
    #[error(transparent)]
    Profile(#[from] CompiledPrivacyProfileValidationErrorV1),
    /// Original canonical encoding refusal, including local resource failure.
    #[error(transparent)]
    Encoding(#[from] norito::core::DecodeAttemptError),
    /// Original native equation/decoding failure.
    #[error(transparent)]
    Native(#[from] AnonymousPgcError),
    /// The original native decoder/canonical-authentication or relation failure.
    #[error(transparent)]
    NativeRead(#[from] AnonymousPgcReadError),
    /// The original native proof violates its closed structural byte bound.
    #[error(transparent)]
    Proof(#[from] PrivacyPgcBootstrapProofValidationError),
    /// This native consumer accepts only the exact Anonymous-PGC protocol.
    #[error("PGC attachment consumer has another protocol")]
    WrongProtocol,
    /// Signed source, trusted network and trusted genesis must be identical.
    #[error("PGC attachment consumer has another network or genesis")]
    NetworkMismatch,
    /// The one native proof is the entire action's attachment shape.
    #[error("PGC attachment consumer requires exactly one proof slot")]
    AttachmentShape,
    /// The public root must be derived by the existing canonical table owner.
    #[error("PGC bootstrap root differs from its canonical account table")]
    RootMismatch,
    /// The native verifier's public results must match this exact input.
    #[error("PGC bootstrap verifier returned inconsistent public values")]
    VerifiedValuesMismatch,
}

/// Reuse the canonical bootstrap digest as this operation's proof-free inputs.
/// The enclosing ActionStatement separately binds operation, authority and path.
///
/// # Errors
/// Returns the original table-validation or canonical-encoding failure.
pub(crate) fn public_inputs_digest(
    bootstrap: &PrivacyPgcAccountBootstrapV1,
) -> Result<ActionPublicInputsDigestV1, BootstrapError> {
    bootstrap.validate()?;
    let digest = norito::core::classify_decode_attempt(|| bootstrap.digest())?;
    Ok(ActionPublicInputsDigestV1::new(*digest.as_bytes()))
}

impl<'owner, 'tx> Invocation<'owner, 'tx> {
    /// Resolve the exact request reference under the already-authorized invocation.
    /// The length is the signed occurrence length, used by the existing privacy budget.
    pub(crate) fn open_pgc_bootstrap(
        &mut self,
        instruction: &BootstrapPrivacyPgcAccountsV1,
    ) -> Result<(AttachmentHandle<'owner, 'tx>, u64), BootstrapError> {
        let mut guard = InvocationGuard {
            frame: self,
            completed: false,
        };
        let result = guard.frame.check_open_pgc_bootstrap(instruction);
        guard.completed = result.is_ok();
        result
    }
    fn check_open_pgc_bootstrap(
        &mut self,
        instruction: &BootstrapPrivacyPgcAccountsV1,
    ) -> Result<(AttachmentHandle<'owner, 'tx>, u64), BootstrapError> {
        let operation =
            ActionOperationV1::NativeInstruction(BootstrapPrivacyPgcAccountsV1::WIRE_ID.to_owned());
        let request = ActionRequest {
            index: instruction.proof_ref.action_index,
            operation: &operation,
            role: ActionRoleV1::Administrative,
            public_inputs_digest: public_inputs_digest(&instruction.bootstrap)?,
        };
        let action = self.action(request)?;
        if instruction.proof_ref.slot_index != 0 || action.attachments.len() != 1 {
            return Err(BootstrapError::AttachmentShape);
        }
        let length = action.attachments[0].length;
        let handle = self.open(
            request,
            instruction.proof_ref.slot_index,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        Ok((handle, length))
    }

    /// Consume one original proof and check its complete native bootstrap relation.
    /// Success returns only the audit digest and completes local custody bookkeeping.
    /// This digest is not a transferable verification capability and applies no effect.
    ///
    /// # Errors
    /// Any error poisons this attempt, even if the caller swallows it. Original
    /// native and codec errors remain available for the runtime's refusal mapper.
    pub(crate) fn consume_pgc_bootstrap(
        &mut self,
        action_index: u32,
        bootstrap: &PrivacyPgcAccountBootstrapV1,
        handle: AttachmentHandle<'_, '_>,
        context: BootstrapContext<'_>,
    ) -> Result<PrivacyPgcBootstrapProofDigestV1, BootstrapError> {
        // Reuse the custody owner's unwind guard so catching a verifier panic
        // inside the surrounding invocation cannot make this attempt reusable.
        let mut guard = InvocationGuard {
            frame: self,
            completed: false,
        };
        let outcome = guard
            .frame
            .check_pgc_bootstrap(action_index, bootstrap, handle, context);
        guard.completed = outcome.is_ok();
        outcome
    }

    fn check_pgc_bootstrap(
        &mut self,
        action_index: u32,
        bootstrap: &PrivacyPgcAccountBootstrapV1,
        handle: AttachmentHandle<'_, '_>,
        context: BootstrapContext<'_>,
    ) -> Result<PrivacyPgcBootstrapProofDigestV1, BootstrapError> {
        self.attempt.ensure_active()?;
        let operation =
            ActionOperationV1::NativeInstruction(BootstrapPrivacyPgcAccountsV1::WIRE_ID.to_owned());
        let request = ActionRequest {
            index: action_index,
            operation: &operation,
            role: ActionRoleV1::Administrative,
            public_inputs_digest: public_inputs_digest(bootstrap)?,
        };
        let action = self.action(request)?;
        if action.attachments.len() != 1 || handle.slot != 0 {
            return Err(BootstrapError::AttachmentShape);
        }
        // Recompute from the original signed owner, never from a guest digest or
        // a previous verification record. I.2 independently checks actual actor/path.
        let intent = self
            .owner
            .source
            .ordered_intent_digest_v1()
            .map_err(CustodyError::from)?;
        let statement = action
            .statement_digest_for_v1(intent)
            .map_err(CustodyError::from)?;
        if self.owner.source.network_id() != Some(context.network_id)
            || context.network_id.as_bytes() != &context.genesis_hash
        {
            return Err(BootstrapError::NetworkMismatch);
        }
        if context.activation.protocol_id != PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1 {
            return Err(BootstrapError::WrongProtocol);
        }
        validate_compiled_privacy_activation_v1(context.activation)?;
        let root = derive_privacy_pgc_account_state_root_v1(
            bootstrap.namespace,
            bootstrap.initial_epoch,
            bootstrap.total_supply,
            &bootstrap.accounts,
        )?;
        if root != bootstrap.initial_root {
            return Err(BootstrapError::RootMismatch);
        }
        // Public input conversion is bounded by the existing closed 16/32/64
        // account validation. No proof Vec or guest-memory copy is constructed.
        let namespace = norito::core::classify_decode_attempt(|| {
            norito::encode_canonical(&bootstrap.namespace)
        })?;
        let public_keys = bootstrap
            .accounts
            .iter()
            .map(|account| {
                TwistedElGamalPublicKeyV1::from_sec1_bytes(account.public_key.as_bytes())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let balances = bootstrap
            .accounts
            .iter()
            .map(|account| {
                TwistedElGamalCiphertextV1::from_sec1_bytes(
                    account.encrypted_balance.left.as_bytes(),
                    account.encrypted_balance.right.as_bytes(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let parameters = AnonymousPgcParametersV1::get()?;
        let native = AnonymousPgcBootstrapStatementV1::new(
            &namespace,
            *root.as_bytes(),
            bootstrap.initial_epoch,
            bootstrap.total_supply,
            &public_keys,
            &balances,
            TranscriptBindingV1 {
                network_id: context.network_id.as_bytes(),
                genesis_hash: context.genesis_hash,
                action_index,
                statement_digest: *statement.as_bytes(),
                parameter_id: *context.activation.parameter_id.as_bytes(),
                parameter_digest: *context.activation.parameter_digest.as_bytes(),
                verifier_digest: *context.activation.verifier_digest.as_bytes(),
                statement_schema_digest: *context.activation.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *context.activation.engine_manifest_digest.as_bytes(),
                generator_digest: parameters.generator_digest(),
            },
        )?;
        // The existing native decoder/verifier is the only arithmetic owner.
        let proof = self.consume(
            request,
            handle,
            AttachmentKindV1::Proof,
            AttachmentRoleV1::ActionProof,
        )?;
        PrivacyPgcBootstrapProofBytesV1::validate_bytes(proof)?;
        let verified = verify_bootstrap_encoded(&native, proof)?;
        if verified.total_supply() != bootstrap.total_supply
            || verified.account_count() != bootstrap.accounts.len()
            || verified.bootstrap_table_digest() != native.bootstrap_table_digest()
        {
            return Err(BootstrapError::VerifiedValuesMismatch);
        }
        let audit_digest = PrivacyPgcBootstrapProofBytesV1::digest_bytes(proof)?;
        self.finish_action(request)?;
        Ok(audit_digest)
    }
}

#[cfg(test)]
mod tests;
