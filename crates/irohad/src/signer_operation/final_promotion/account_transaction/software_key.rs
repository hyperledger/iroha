//! One-use software custody for an already authorized final-promotion account transaction.
//!
//! The account continuation owns finalized Checks, spending approval and signature release.
//! This adapter only loads the configured role-15 key and signs the exact typed request once.
//! It does not submit a transaction or attest that Reserve was applied.

use std::path::Path;

use iroha_core::query::final_promotion_account_custody::observation::validate_final_promotion_account_transaction_envelope_v1;
use iroha_crypto::{ExposedPrivateKey, KeyPair, Signature};
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    sorafs::final_promotion_authority::FinalPromotionAuthorityActionV1,
    transaction::{Executable, TransactionBuilder, TransactionPayload},
};
use iroha_primitives::production_identity::is_production_identity_v1;
use sorafs_manifest::signer::{
    custody::SignerCustodyBindingV1,
    protocol::{
        SIGNER_MAX_ID_BYTES_V1, SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1,
    },
};
use zeroize::Zeroizing;

use super::{FinalPromotionAccountKeyRequestV1, FinalPromotionAccountTransactionErrorV1 as Error};
use crate::runtime_credential::load_bounded_runtime_credential_v1;

const MAX_CREDENTIAL_BYTES_V1: usize = 16 * 1024 + 256;
const ROLE_15_SOFTWARE_HANDLE_PREFIX_V1: &str =
    "software://sorafs/final-promotion-account-transaction/";

/// A single protected role-15 software key use pinned to one complete configured binding.
///
/// Construction authenticates the supervisor credential's filesystem source and exact public
/// key. The binding itself becomes authority only when the enclosing account continuation has
/// consumed its fresh executed custody Checks. This value is consumed by one signing attempt;
/// an ambiguous caller result cannot retry the same in-memory capability.
pub struct SoftwareFinalPromotionAccountKeyV1 {
    binding: SignerCustodyBindingV1,
    keypair: KeyPair,
}

impl SoftwareFinalPromotionAccountKeyV1 {
    /// Load one canonical Ed25519 private-key multihash from an owner-only supervisor credential.
    ///
    /// The caller must supply the independently reviewed, complete role-15 binding. No runtime
    /// handle is resolved into a pathname, and no private key is accepted in configuration.
    ///
    /// # Errors
    /// Rejects the wrong role or purpose, an unpinned software handle, invalid generation, an
    /// insecure credential source or a private key that does not match the configured public key.
    pub fn load_from_supervisor_credential(
        path: &Path,
        binding: SignerCustodyBindingV1,
    ) -> Result<Self, Error> {
        validate_binding(&binding)?;
        let bytes = load_bounded_runtime_credential_v1(path, 2, MAX_CREDENTIAL_BYTES_V1)
            .map_err(|_| Error::Provider)?;
        let literal = bytes
            .strip_suffix(b"\n")
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or(Error::Provider)?;
        let exposed: ExposedPrivateKey = literal.parse().map_err(|_| Error::Provider)?;
        let canonical = Zeroizing::new(
            exposed
                .try_to_multihash_string()
                .map_err(|_| Error::Provider)?,
        );
        if canonical.as_str() != literal || exposed.0.algorithm() != binding.algorithm.algorithm() {
            return Err(Error::Provider);
        }
        let keypair = KeyPair::from_private_key(exposed.0).map_err(|_| Error::Provider)?;
        if keypair.public_key() != &binding.public_key {
            return Err(Error::Provider);
        }
        Ok(Self { binding, keypair })
    }

    /// Consume this credential for exactly one authorized ordinary transaction prehash.
    ///
    /// The request has no public constructor: the account continuation creates it only after
    /// fresh role-14 and role-15 Current Checks and holds the signature private until its two
    /// post-key Checks succeed. This adapter independently checks the complete binding, native
    /// action and prehash before touching the key, then verifies its own signature.
    ///
    /// # Errors
    /// Rejects a changed key generation, handle, deployment, payload or signing message.
    pub fn sign(self, request: &FinalPromotionAccountKeyRequestV1<'_>) -> Result<Signature, Error> {
        if request.binding() != &self.binding {
            return Err(Error::Binding);
        }
        validate_request_payload(&self.binding, request.payload(), request.signing_message())?;
        let signature = Signature::try_new(self.keypair.private_key(), request.signing_message())
            .map_err(|_| Error::Provider)?;
        signature
            .verify(&self.binding.public_key, request.signing_message())
            .map_err(|_| Error::Provider)?;
        Ok(signature)
    }
}

fn validate_binding(binding: &SignerCustodyBindingV1) -> Result<(), Error> {
    binding.validate().map_err(|_| Error::Binding)?;
    if binding.role != SignerRoleV1::FinalPromotionAccountTransaction
        || binding.algorithm != SignerKeyAlgorithmV1::Ed25519
        || !matches!(
            binding.purpose,
            SignerPurposeBindingV1::FinalPromotionAccountTransaction { .. }
        )
        || !binding
            .runtime_handle
            .strip_prefix(ROLE_15_SOFTWARE_HANDLE_PREFIX_V1)
            .is_some_and(|identity| is_production_identity_v1(identity, SIGNER_MAX_ID_BYTES_V1))
        || !binding
            .key_handle
            .strip_prefix(ROLE_15_SOFTWARE_HANDLE_PREFIX_V1)
            .is_some_and(|identity| is_production_identity_v1(identity, SIGNER_MAX_ID_BYTES_V1))
        || iroha_config::parameters::validate_production_runtime_handle(&binding.runtime_handle)
            .is_err()
        || iroha_config::parameters::validate_production_runtime_handle(&binding.key_handle)
            .is_err()
    {
        return Err(Error::Binding);
    }
    Ok(())
}

pub(super) fn validate_request_payload(
    binding: &SignerCustodyBindingV1,
    payload: &TransactionPayload,
    message: &[u8],
) -> Result<(), Error> {
    validate_final_promotion_account_transaction_envelope_v1(payload)
        .map_err(|_| Error::Payload)?;
    let SignerPurposeBindingV1::FinalPromotionAccountTransaction { deployment_id } =
        &binding.purpose
    else {
        return Err(Error::Binding);
    };
    let Executable::Instructions(instructions) = &payload.instructions else {
        return Err(Error::Payload);
    };
    let instruction = instructions
        .first()
        .and_then(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
        })
        .ok_or(Error::Payload)?;
    if payload.authority != AccountId::new(binding.public_key.clone())
        || payload
            .network_id()
            .map(iroha_data_model::NetworkId::as_bytes)
            != Some(&binding.network_id)
        || instructions.len() != 1
        || instruction.deployment_id != *deployment_id
        || !matches!(
            instruction.action,
            FinalPromotionAuthorityActionV1::Reserve(_)
                | FinalPromotionAuthorityActionV1::Complete(_)
        )
    {
        return Err(Error::Payload);
    }
    let expected = TransactionBuilder::from_payload(payload.clone())
        .map_err(|_| Error::Payload)?
        .payload_hash_bytes();
    if message != expected.as_slice() {
        return Err(Error::Payload);
    }
    Ok(())
}
