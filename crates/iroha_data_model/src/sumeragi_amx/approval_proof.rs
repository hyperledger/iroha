//! Exact direct debit approval at an independently authenticated participant World cut.
//!
//! This is historical permission evidence. Native execution rechecks the current grant;
//! an older proof cannot override revocation or authorize a different transaction.

use super::AmxDebitApprovalV1;
use crate::{
    account::AccountId,
    permission::Permissions,
    sorafs::stream_token_custody::proof::borrowed,
    sumeragi_finality::{
        FinalityError, MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
        VerifiedSumeragiBlock, WorldStateSnapshotV1,
    },
};
use iroha_crypto::Hash;

/// Finite response bound inherited from the canonical complete World reader.
pub const MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1: usize = MAX_WORLD_STATE_SNAPSHOT_BYTES_V1;
/// Maximum direct permission originals exposed by this scoped reader.
pub const MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1: usize = 256;
/// Bound on the canonical direct permission row and independently selected terms.
pub const MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1: usize = 64 * 1024;

fn invalid(error: impl std::fmt::Display) -> FinalityError {
    FinalityError(error.to_string())
}

#[cfg(test)]
#[path = "approval_proof/tests.rs"]
mod tests;

/// Data-only complete World preimages and the selected relay's direct permissions.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields, no_fast_from_json)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxDebitApprovalProofV1")]
pub struct AmxDebitApprovalProofV1 {
    /// Every canonical World hash preimage at the caller's selected certified cut.
    pub world: WorldStateSnapshotV1,
    /// Original direct permission row; roles never provide this scoped consent.
    pub relay_permissions: Permissions,
}

/// Encoder for the sole proof layout which borrows the original native values.
#[derive(norito::derive::NoritoSerialize, norito::derive::JsonSerialize)]
pub struct AmxDebitApprovalProofRefV1<'a> {
    world: borrowed::Value<'a, WorldStateSnapshotV1>,
    relay_permissions: borrowed::Value<'a, Permissions>,
}
impl norito::NoritoSchema for AmxDebitApprovalProofRefV1<'_> {
    fn nominal_name() -> String {
        <AmxDebitApprovalProofV1 as norito::NoritoSchema>::nominal_name()
    }
    fn frame_name() -> String {
        <AmxDebitApprovalProofV1 as norito::NoritoSchema>::frame_name()
    }
}
impl<'a> AmxDebitApprovalProofRefV1<'a> {
    /// Borrow exact originals without cloning the World or creating current authority.
    #[must_use]
    pub fn new(world: &'a WorldStateSnapshotV1, relay_permissions: &'a Permissions) -> Self {
        Self {
            world: borrowed::Value(world),
            relay_permissions: borrowed::Value(relay_permissions),
        }
    }
}

/// Exact direct consent authenticated at one caller-selected participant decision.
///
/// No decoder or public constructor can manufacture this result. Its height is a historical
/// fact, not a claim that the permission remains current or that a debit has executed.
#[derive(Debug)]
pub struct VerifiedAmxDebitApprovalV1 {
    approval: AmxDebitApprovalV1,
    relay: AccountId,
    height: u64,
    context_id: Hash,
}
impl VerifiedAmxDebitApprovalV1 {
    /// Exact independently selected terms, roots and debit balance.
    #[must_use]
    pub fn approval(&self) -> &AmxDebitApprovalV1 {
        &self.approval
    }
    /// Exact registered recipient of the direct permission at this cut.
    #[must_use]
    pub fn relay(&self) -> &AccountId {
        &self.relay
    }
    /// Authenticated height; the caller separately selects and checks freshness.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }
    /// Exact authenticated consensus header and execution result.
    #[must_use]
    pub fn context_id(&self) -> Hash {
        self.context_id
    }
}

impl AmxDebitApprovalProofV1 {
    /// Decode one canonical proof frame under finite portable transport/allocation limits.
    /// # Errors
    /// Empty, oversized, malformed, noncanonical or resource-exhausting input.
    pub fn decode_frame(bytes: &[u8]) -> Result<Self, norito::Error> {
        if bytes.is_empty() || bytes.len() > MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1 {
            return Err(norito::Error::Message(
                "AMX debit approval proof exceeds its bound".into(),
            ));
        }
        norito::decode_canonical_with_limits(
            bytes,
            norito::DecodeLimits::new(
                MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
                MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1,
                128 * 1024 * 1024,
                64,
            ),
        )
    }

    /// Authenticate exact owner-issued consent against independently selected private finality.
    ///
    /// No authority comes from supplied root labels, a role, or the relay possessing the debit
    /// owner's key. Only the exact canonical direct permission at this cut is established.
    /// Current execution still checks revocation. A proof never permits signing other terms.
    /// # Errors
    /// Wrong root, instance, terms, schema, permission or typed preimage; concealed state;
    /// genesis, malformed data or exceeded finite reader bounds.
    pub fn verify(
        &self,
        expected_approval: &AmxDebitApprovalV1,
        expected_relay: &AccountId,
        expected_schema: Hash,
        block: &VerifiedSumeragiBlock,
    ) -> Result<VerifiedAmxDebitApprovalV1, FinalityError> {
        let instance = block
            .native_instance_id()
            .ok_or_else(|| invalid("AMX debit approval requires a certified successor"))?;
        if !cfg!(all(test, sumeragi_model_mutation = "DM38")) {
            expected_approval
                .validate_root(
                    block.commitment().schedule.current.network_id,
                    block.root_scope(),
                    instance,
                )
                .map_err(invalid)?;
        }
        if block.height() < 2
            || self.world.schema_hash != expected_schema
            || norito::canonical_frame_len(expected_approval).map_err(invalid)?
                > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
            || norito::canonical_frame_len(expected_relay).map_err(invalid)?
                > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
            || self.relay_permissions.len() > MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1
            || norito::canonical_frame_len(&self.relay_permissions).map_err(invalid)?
                > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
            || norito::canonical_frame_len(self).map_err(invalid)?
                > MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1
        {
            return Err(invalid(
                "AMX debit approval differs from the selected schema or finite bounds",
            ));
        }
        let mut matched = false;
        for permission in &self.relay_permissions {
            if expected_approval
                .matches_permission(permission)
                .map_err(invalid)?
            {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(invalid(
                "AMX debit approval requires the exact direct CanPrepareAmx grant",
            ));
        }
        let world = self.world.authenticate(block)?;
        world.verify_account_key_present(expected_relay)?;
        world.verify_account_key_present(expected_approval.debited_asset.account())?;
        world.verify_asset_definition_key_present(expected_approval.debited_asset.definition())?;
        world.verify_table_value(
            "world.account_permissions",
            expected_relay,
            &self.relay_permissions,
        )?;
        Ok(VerifiedAmxDebitApprovalV1 {
            approval: expected_approval.clone(),
            relay: expected_relay.clone(),
            height: world.height(),
            context_id: world.context_id(),
        })
    }
}
