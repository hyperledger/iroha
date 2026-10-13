//! Public SCCP v1 reads on the client's reusable blocking runtime (`specs/sccp.md` §6).

use crate::client::sccp::SccpFinalityAt;

use super::{Client, RuntimeOwner};
use crate::{
    Result,
    client::sccp::{SccpDirection, SccpProofHeightV1},
};
use iroha_data_model::{bridge::SccpNetworkV1, sccp::registry::SccpRouteV1};
use iroha_sccp::api::{
    SccpCapabilitiesV1, SccpCertificateV1, SccpControlPageV1, SccpControlProofBundleV1,
    SccpGenerationV1, SccpGovernanceProposalDetailV1, SccpHistoryPathViewV1,
    SccpLcCheckpointCoverV1, SccpLightClientDetailV1, SccpMessageProofBundleV1,
    SccpMessageStatusV1, SccpOutboundPageV1, SccpRecentMessagesV1, SccpRotationV1,
};

/// Blocking SCCP reads backed by the asynchronous SCCP capability.
///
/// Committee reads carry native BLS generation metadata; attestation roster reads are absent:
///
/// ```compile_fail,E0599
/// fn removed_current_roster(api: &iroha::blocking::sccp::Sccp<'_>) {
///     let _ = api.current_roster();
/// }
/// ```
///
/// ```compile_fail,E0599
/// fn removed_roster(api: &iroha::blocking::sccp::Sccp<'_>) {
///     let _ = api.roster(1);
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Sccp<'a> {
    inner: crate::client::sccp::Sccp<'a>,
    runtime: &'a RuntimeOwner,
}

impl Client {
    /// Access the public SCCP read API through this facade's reusable runtime.
    #[must_use]
    pub fn sccp(&self) -> Sccp<'_> {
        Sccp {
            inner: self.inner.sccp(),
            runtime: &self.runtime,
        }
    }
}

impl Sccp<'_> {
    /// Read the original native finality certificate selected by `at`.
    ///
    /// # Errors
    /// Preserves the asynchronous client's source and transport failures.
    pub fn finality(&self, at: SccpFinalityAt) -> Result<SccpCertificateV1> {
        self.runtime.block_on(self.inner.finality(at))?
    }

    /// Read the Taira identity, parameters and light-client profiles.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn capabilities(&self) -> Result<SccpCapabilitiesV1> {
        self.runtime.block_on(self.inner.capabilities())?
    }

    /// Read current committee metadata; authenticate its keys through signed history.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn current_committee(&self) -> Result<SccpGenerationV1> {
        self.runtime.block_on(self.inner.current_committee())?
    }

    /// Read one generation's retained keys and current liability.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn committee(&self, generation: u64) -> Result<SccpGenerationV1> {
        self.runtime.block_on(self.inner.committee(generation))?
    }

    /// Read native rotation certificates after an independently pinned generation.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn rotations(&self, after_generation: u64, limit: usize) -> Result<Vec<SccpRotationV1>> {
        self.runtime
            .block_on(self.inner.rotations(after_generation, limit))?
    }

    /// Read the nonzero per-subject governance revisions.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn governance_revisions(
        &self,
    ) -> Result<Vec<iroha_data_model::sccp::governance::SccpGovernanceBaseRevisionV1>> {
        self.runtime.block_on(self.inner.governance_revisions())?
    }

    /// Read governance readiness at one committed state observation.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn governance_readiness(&self) -> Result<iroha_sccp::api::SccpGovernanceReadinessV1> {
        self.runtime.block_on(self.inner.governance_readiness())?
    }

    /// Read every open SCCP governance proposal, oldest first.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn governance_proposals(
        &self,
    ) -> Result<Vec<iroha_sccp::api::SccpGovernanceProposalStatusV1>> {
        self.runtime.block_on(self.inner.governance_proposals())?
    }

    /// Read every installed inbound light client.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn light_clients(
        &self,
    ) -> Result<Vec<iroha_data_model::sccp::light_client::SccpLightClientV1>> {
        self.runtime.block_on(self.inner.light_clients())?
    }

    /// Read the stored consensus sets of `network`'s light client.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn light_client_sets(
        &self,
        network: iroha_data_model::bridge::SccpNetworkV1,
    ) -> Result<Vec<iroha_data_model::sccp::light_client::SccpLcConsensusSetV1>> {
        self.runtime
            .block_on(self.inner.light_client_sets(network))?
    }

    /// Read every route.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn registry(&self) -> Result<Vec<SccpRouteV1>> {
        self.runtime.block_on(self.inner.registry())?
    }

    /// Read effective revision holds and scalar reconciliation accounting.
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn forgery_hold(
        &self,
        query: iroha_sccp::api::SccpForgeryHoldQuery,
    ) -> Result<iroha_sccp::api::SccpForgeryHoldViewV1> {
        self.runtime.block_on(self.inner.forgery_hold(query))?
    }

    /// Read original fast-pause state and explicit current-seat eligibility availability.
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn fast_pause(&self) -> Result<iroha_sccp::api::SccpFastPauseViewV1> {
        self.runtime.block_on(self.inner.fast_pause())?
    }

    /// Read a retained original anchor witness at one nonzero committed height.
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn anchor_witness(
        &self,
        height: std::num::NonZeroU64,
    ) -> Result<iroha_sccp::api::SccpAnchorWitnessBundleV1> {
        self.runtime.block_on(self.inner.anchor_witness(height))?
    }

    /// Read an exact original committed SCCP forgery report.
    /// # Errors
    /// Preserves the asynchronous operation or runtime error.
    pub fn evidence(&self, id: &[u8; 32]) -> Result<iroha_sccp::api::SccpForgeryEvidenceStatusV1> {
        self.runtime.block_on(self.inner.evidence(id))?
    }

    /// Read a bounded page after an exclusive original evidence id.
    /// # Errors
    /// Preserves the asynchronous operation or runtime error.
    pub fn evidence_page(
        &self,
        after: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<iroha_sccp::api::SccpForgeryEvidencePageV1> {
        self.runtime
            .block_on(self.inner.evidence_page(after, limit))?
    }

    /// Read the status union of one message id (outbound, inbound or unknown).
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn message(&self, message_id: &[u8; 32]) -> Result<SccpMessageStatusV1> {
        self.runtime.block_on(self.inner.message(message_id))?
    }

    /// Read the newest records of one direction.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn recent_messages(
        &self,
        direction: SccpDirection,
        network: Option<SccpNetworkV1>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<SccpRecentMessagesV1> {
        self.runtime.block_on(
            self.inner
                .recent_messages(direction, network, before, limit),
        )?
    }

    /// Read the outbound records of one route revision by nonce.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn outbound(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        from_nonce: u64,
        limit: usize,
    ) -> Result<SccpOutboundPageV1> {
        self.runtime
            .block_on(self.inner.outbound(network, revision, from_nonce, limit))?
    }

    /// Read the destination controls of one route revision.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn controls(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        after_nonce: u64,
        limit: usize,
    ) -> Result<SccpControlPageV1> {
        self.runtime
            .block_on(self.inner.controls(network, revision, after_nonce, limit))?
    }

    /// Read the history path of one SCCP block.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn history(&self, height: u64, size: Option<u64>) -> Result<SccpHistoryPathViewV1> {
        self.runtime.block_on(self.inner.history(height, size))?
    }

    /// Read one inbound light client with its freshness and stored data.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn light_client(&self, network: SccpNetworkV1) -> Result<SccpLightClientDetailV1> {
        self.runtime.block_on(self.inner.light_client(network))?
    }

    /// Read the stored checkpoints anchoring a proof of source height `covering`.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn light_client_checkpoints(
        &self,
        network: SccpNetworkV1,
        covering: u64,
    ) -> Result<SccpLcCheckpointCoverV1> {
        self.runtime
            .block_on(self.inner.light_client_checkpoints(network, covering))?
    }

    /// Read one SCCP governance proposal in any phase.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn governance_proposal(
        &self,
        content_id: &[u8; 32],
    ) -> Result<SccpGovernanceProposalDetailV1> {
        self.runtime
            .block_on(self.inner.governance_proposal(content_id))?
    }

    /// Read the proof bundle of one outbound message.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn message_proof(
        &self,
        message_id: &[u8; 32],
        at: SccpProofHeightV1,
    ) -> Result<SccpMessageProofBundleV1> {
        self.runtime
            .block_on(self.inner.message_proof(message_id, at))?
    }

    /// Read the proof bundle of one destination control.
    ///
    /// # Errors
    /// Returns the asynchronous operation error or a typed runtime rejection.
    pub fn control_proof(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        control_nonce: u64,
        at: SccpProofHeightV1,
    ) -> Result<SccpControlProofBundleV1> {
        self.runtime.block_on(
            self.inner
                .control_proof(network, revision, control_nonce, at),
        )?
    }
}
