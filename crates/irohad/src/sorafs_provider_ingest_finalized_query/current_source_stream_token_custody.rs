//! Read-only native `StreamToken` custody control at a source assignment's committed head.
//!
//! This pairs two genuine State/Kura inputs. It does not attest a signed custody statement,
//! publish council admission or advert revocation, pin HTTPS transport, or issue a grant.

use super::{ArchivedProviderIngestFinalizedLedgerV1, ProviderIngestCurrentSourceAssignmentV1};
use iroha_core::{
    query::stream_token_custody::{
        StreamTokenCustodyControlErrorV1, StreamTokenCustodyControlSnapshotV1,
        read_stream_token_custody_control_at_v1,
    },
    state::StateReadOnly as _,
};
use iroha_data_model::NetworkId;
use sorafs_manifest::signer::{
    custody::{SignerCustodyAnchorV1, SignerCustodyBindingV1},
    protocol::SignerPurposeBindingV1,
    stream_token::stream_token_binding_digest_v1,
};
use sorafs_node::{
    ProviderIngestFinalizedCursorV1, ProviderIngestFinalizedLedgerErrorV1,
    provider_ingest_runtime::ProviderIngestSourceRequestV1,
};

/// Current native `StreamToken` control paired with one exact source assignment.
///
/// This is public, payload-free, read-only evidence. Even an enrolled and unrevoked control
/// is not a verified signed custody statement or an HTTPS/StreamToken grant authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProviderIngestCurrentSourceStreamTokenCustodyV1 {
    assignment: ProviderIngestCurrentSourceAssignmentV1,
    control: StreamTokenCustodyControlSnapshotV1,
}

impl ProviderIngestCurrentSourceStreamTokenCustodyV1 {
    /// Exact current source assignment observed with the native control.
    pub const fn assignment(&self) -> &ProviderIngestCurrentSourceAssignmentV1 {
        &self.assignment
    }

    /// Public native control state, including its key policy, enrollment head and revocations.
    #[must_use]
    pub const fn control(&self) -> &StreamTokenCustodyControlSnapshotV1 {
        &self.control
    }

    /// Exact native role-state digest at the source assignment's committed head.
    #[must_use]
    pub const fn control_anchor(&self) -> SignerCustodyAnchorV1 {
        self.control.anchor
    }
}

/// Join independently checked assignment and native control snapshots at one head.
///
/// This helper rejects a stale head, substituted provider/key, unconfigured or revoked role,
/// and inconsistent native control. It cannot establish council admission or grant authority.
pub(super) fn join_current_source_stream_token_custody(
    assignment: ProviderIngestCurrentSourceAssignmentV1,
    expected_binding: &SignerCustodyBindingV1,
    state_head: ProviderIngestFinalizedCursorV1,
    control: StreamTokenCustodyControlSnapshotV1,
) -> Result<ProviderIngestCurrentSourceStreamTokenCustodyV1, ProviderIngestFinalizedLedgerErrorV1> {
    let source = assignment.source_provider_id();
    if stream_token_binding_digest_v1(expected_binding).is_err()
        || expected_binding.network_id != *assignment.network_id().as_bytes()
        || !matches!(
            &expected_binding.purpose,
            SignerPurposeBindingV1::StreamToken { provider_id } if *provider_id == source
        )
        || assignment.finalized_head() != state_head
        || control.anchor.height != state_head.height
        || control.anchor.block_hash != state_head.block_hash
        || control.anchor.state_digest == [0; 32]
        || control.state.validate().is_err()
        || control.state.policy.binding != *expected_binding
        || control.state.active_head.is_none()
        || control.state.signer_revoked
        || control.state.attester_revoked
    {
        return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
    }
    Ok(ProviderIngestCurrentSourceStreamTokenCustodyV1 {
        assignment,
        control,
    })
}

impl ArchivedProviderIngestFinalizedLedgerV1 {
    /// Read current native `StreamToken` control for a finalized source assignment.
    ///
    /// The expected public binding is independently configured, then checked against the
    /// consensus-owned native record. Both reads must observe the same qualified archive head;
    /// no cached advert, local directory, or caller-provided custody claim becomes authority.
    /// An external resolver must still verify the signed custody use statement and complete
    /// finalized council admission/advert/revocation and transport-pin lineage before a grant.
    ///
    /// # Errors
    /// Rejects mismatched, unenrolled or revoked custody and any changed head/generation.
    /// Missing, corrupt or unstable native State/Kura/archive evidence fails closed.
    pub fn read_current_source_stream_token_custody_for_resolver(
        &self,
        network_id: NetworkId,
        source_provider_id: [u8; 32],
        request: &ProviderIngestSourceRequestV1,
        expected_assignment_revision: u64,
        expected_binding: &SignerCustodyBindingV1,
    ) -> Result<ProviderIngestCurrentSourceStreamTokenCustodyV1, ProviderIngestFinalizedLedgerErrorV1>
    {
        if stream_token_binding_digest_v1(expected_binding).is_err()
            || expected_binding.network_id != *network_id.as_bytes()
            || !matches!(
                &expected_binding.purpose,
                SignerPurposeBindingV1::StreamToken { provider_id } if *provider_id == source_provider_id
            )
        {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let generation_before = self
            .archive
            .health_generation()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let assignment = self.read_current_source_assignment_for_resolver(
            network_id,
            source_provider_id,
            request,
            expected_assignment_revision,
        )?;
        let view = self.state.query_view();
        if !std::ptr::eq(view.kura(), self.kura.as_ref()) || view.network_id != network_id {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Unavailable);
        }
        let height = u64::try_from(view.height())
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let block_hash = view
            .latest_block_hash()
            .map(|hash| *hash.as_ref())
            .filter(|hash| *hash != [0; 32])
            .ok_or(ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        let state_head = ProviderIngestFinalizedCursorV1 { height, block_hash };
        if assignment.finalized_head() != state_head {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        let control = read_stream_token_custody_control_at_v1(&view, expected_binding, height)
            .map_err(|error| match error {
                StreamTokenCustodyControlErrorV1::BindingMismatch => {
                    ProviderIngestFinalizedLedgerErrorV1::Rejected
                }
                _ => ProviderIngestFinalizedLedgerErrorV1::Unavailable,
            })?
            .ok_or(ProviderIngestFinalizedLedgerErrorV1::Rejected)?;
        drop(view);
        let rechecked = self.read_current_source_assignment_for_resolver(
            network_id,
            source_provider_id,
            request,
            expected_assignment_revision,
        )?;
        let generation_after = self
            .archive
            .health_generation()
            .map_err(|_| ProviderIngestFinalizedLedgerErrorV1::Unavailable)?;
        if generation_before != generation_after || assignment != rechecked {
            return Err(ProviderIngestFinalizedLedgerErrorV1::Rejected);
        }
        join_current_source_stream_token_custody(assignment, expected_binding, state_head, control)
    }
}
