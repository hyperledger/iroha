//! Current issuer checks for one signed AXT spend, without source admission.

use iroha_data_model::nexus::{
    AxtAnchoredSpendV1, AxtAnchoredSpendValidationErrorV1, AxtBinding, AxtHandleIssuerContextV1,
};
use ivm::PreparedContract;
use mv::storage::StorageReadOnly;
use thiserror::Error;

use super::{StateReadOnly, StateTransaction, WorldReadOnly};
use crate::nexus::space_directory::{AxtIssuerResolutionError, resolve_axt_issuer_binding};

/// Failure to confirm the issuer claims against the current transaction view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[allow(dead_code)]
pub(crate) enum AxtCurrentIssuerErrorV1 {
    /// A positive consensus ledger slot is required for spend application.
    #[error("AXT issuer verification requires a positive consensus ledger slot")]
    ZeroLedgerSlot,
    /// No active policy authorizes this dataspace.
    #[error("AXT issuer verification has no active dataspace policy")]
    MissingPolicy,
    /// The current manifest or lane differs from the signed handle.
    #[error("AXT spend differs from the current manifest or lane policy")]
    PolicyMismatch,
    /// Authority changed in this transaction or an accepted earlier block transaction.
    #[error("AXT issuer authority has a pending generation transition")]
    PendingAuthorizationTransition,
    /// The permanent handle counter/generation is absent, stale, or exhausted.
    #[error("AXT spend does not match the permanent handle counter and generation")]
    HandleCounter,
    /// The asset is absent or lacks its exact registration incarnation.
    #[error("AXT spend has no current registered asset incarnation")]
    AssetIncarnation,
    /// Current committed issuer identity or key resolution failed.
    #[error("AXT current issuer resolution failed: {0}")]
    Issuer(AxtIssuerResolutionError),
    /// The exact executing envelope differs from the signed handle binding.
    #[error("AXT spend differs from the executing envelope binding")]
    InvocationBinding,
    /// The authorization has expired relative to consensus ledger time.
    #[error("AXT spend issuer authorization has expired")]
    Expired,
    /// This issuer nonce was consumed by an earlier transaction.
    #[error("AXT spend issuer nonce has already been consumed")]
    NonceConsumed,
    /// A public binding or either issuer signature failed verification.
    #[error("AXT spend issuer authentication failed: {0}")]
    Authentication(AxtAnchoredSpendValidationErrorV1),
}

impl StateTransaction<'_, '_> {
    /// Check both issuer signatures and current authority from this transaction view.
    ///
    /// All policy, key, incarnation, counter, and nonce reads borrow this one
    /// immutable transaction overlay. Expiry uses its executing block's consensus
    /// timestamp and configured slot length; local wall-clock time is never read.
    /// The permanent counter owns the generation and next nonce. Sticky local
    /// and block transition markers reject revoked/reactivated authority before
    /// the permanent generation advances at block finalization, so restoring
    /// equal policy/key bytes cannot revive the old generation.
    ///
    /// `invocation` supplies a validated ABI V1 artifact, but the caller must still
    /// establish that it is the currently authorized deployment being executed.
    /// The source anchor is an issuer-signed claim only. This method neither
    /// authenticates finalized source State/receipt/occurrence nor verifies FASTPQ,
    /// and its unit result grants no spend authority or replay reservation.
    ///
    /// TODO: Compose these checks with the complete finalized-State resolver,
    /// source proof and current deployment owner before enabling one atomic
    /// nonce/budget/effect admission path. Production admission remains closed.
    ///
    /// # Errors
    /// Rejects absent or changed current authority, stale counters/nonces,
    /// expired authorization, inconsistent bindings, and invalid signatures.
    #[allow(dead_code)]
    pub(crate) fn verify_current_axt_spend_issuer_claims_v1(
        &self,
        spend: &AxtAnchoredSpendV1,
        invocation: &PreparedContract,
        envelope_binding: AxtBinding,
    ) -> Result<(), AxtCurrentIssuerErrorV1> {
        let slot = self.axt_current_slot();
        if slot == 0 {
            return Err(AxtCurrentIssuerErrorV1::ZeroLedgerSlot);
        }
        let world = &self.world;
        let handle = &spend.draft.handle;
        let dataspace = spend.draft.intent.asset_dsid;
        if world.axt_authorization_transitioned.contains(&dataspace)
            || self
                .block_axt_authorization_transitioned
                .contains(&dataspace)
        {
            return Err(AxtCurrentIssuerErrorV1::PendingAuthorizationTransition);
        }
        let policies = world.axt_policies();
        let policy = policies
            .get(&dataspace)
            .filter(|policy| policy.manifest_root != [0; 32])
            .ok_or(AxtCurrentIssuerErrorV1::MissingPolicy)?;
        if (&handle.manifest_view_root, handle.target_lane)
            != (&policy.manifest_root, policy.target_lane)
            || super::consensus_lane_dataspace_at_height(
                policy.target_lane,
                self.nexus(),
                self.block_height(),
            ) != Some(dataspace)
        {
            return Err(AxtCurrentIssuerErrorV1::PolicyMismatch);
        }
        let mut counter = world
            .axt_handle_counters()
            .get(&dataspace)
            .copied()
            .ok_or(AxtCurrentIssuerErrorV1::HandleCounter)?;
        counter
            .try_advance(handle.handle_era, handle.sub_nonce)
            .map_err(|_| AxtCurrentIssuerErrorV1::HandleCounter)?;
        if handle.axt_binding != envelope_binding {
            return Err(AxtCurrentIssuerErrorV1::InvocationBinding);
        }
        if world
            .asset_definitions()
            .get(&handle.asset_definition_id)
            .is_none()
        {
            return Err(AxtCurrentIssuerErrorV1::AssetIncarnation);
        }
        let incarnation = world
            .axt_asset_incarnations()
            .get(&handle.asset_definition_id)
            .copied()
            .filter(|incarnation| incarnation.validate().is_ok())
            .ok_or(AxtCurrentIssuerErrorV1::AssetIncarnation)?;
        let issuer = resolve_axt_issuer_binding(world, dataspace, policy.manifest_root)
            .map_err(AxtCurrentIssuerErrorV1::Issuer)?;
        let context = AxtHandleIssuerContextV1 {
            network_id: *self.network_id(),
            asset_dsid: dataspace,
            asset_definition_incarnation: incarnation,
            issuer: issuer.issuer,
            issuer_manifest_root: policy.manifest_root,
            code_root: invocation.code_hash().into(),
            abi_version: u16::from(invocation.metadata().abi_version),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        };
        spend
            .verify_issuer_signatures_v1(context, spend.authorization.anchor, &issuer.public_key)
            .map_err(AxtCurrentIssuerErrorV1::Authentication)?;
        let timing = self.nexus().axt;
        let expiry = ivm::axt::expiry_slot_with_skew(
            spend.authorization.expiry_slot,
            timing.slot_length_ms,
            timing.max_clock_skew_ms,
            handle.max_clock_skew_ms,
        );
        if slot > expiry {
            return Err(AxtCurrentIssuerErrorV1::Expired);
        }
        if world
            .axt_spend_nonce_ledger()
            .get(&spend.replay_key_v1())
            .is_some()
        {
            return Err(AxtCurrentIssuerErrorV1::NonceConsumed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
