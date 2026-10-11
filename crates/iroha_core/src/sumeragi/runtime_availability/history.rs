//! One retained authenticated archive scan, bounded to a captured original State publication.

#[cfg(test)]
mod source_refusal_tests;

use crate::execution_attempt::{
    ExecutionAttemptError as Attempt, canonical_decode_attempt_error, norito_decode_attempt_error,
};
use crate::sumeragi::{
    block_store::certificate_read::CertificateReadError,
    certified_chain::{PrefixArtifactsError, PrefixArtifactsRead},
    driver::payload_build::PayloadBuildError,
};

use super::{invalid, pending, selection::LaneSelection};
use crate::query::native_receipts::lane_payload::{
    LaneAuthority, LaneAuthorityRead, LanePayload, LanePayloadError, LanePayloadRead,
};
use crate::{
    kura::Kura,
    query::native_context_archive::{
        NativeContextArchive, NativeContextArchiveError, NativeContextRead,
    },
    state::{
        NativeExecutionEvidenceLimits, NativeExecutionEvidenceVerifier, State, StateReadOnly,
        StateView, WorldReadOnly,
    },
};
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, consensus::LaneEvidenceScope},
    sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
};
use iroha_model_base::topology::LaneId;
use std::{io, num::NonZeroUsize, sync::Arc};

enum TipPayloadRead {
    Pending(LanePayloadRead),
    Ready(LanePayload),
}

enum AuthorityRead {
    Payload(LanePayloadRead),
    Config(LaneAuthorityRead),
    Ready(LaneAuthority),
}

/// A fixed original State cut captured without disk I/O or another State view. Its fields
/// are private and it has no decoder. Installation must still recheck the same generation.
pub(in crate::sumeragi) struct HistoryCapture {
    generation: u64,
    original_tip: crate::state::NativeExecutionTip,
    kura: Arc<Kura>,
    budget: AllocationBudget,
    network: iroha_data_model::NetworkId,
    chain_id: iroha_model_base::chain::ChainId,
    policy: Option<(u64, u64)>,
}
impl std::fmt::Debug for HistoryCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryCapture")
            .field("generation", &self.generation)
            .field("height", &self.original_tip.height())
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}
impl HistoryCapture {
    // The caller samples this generation before acquiring this exact original State view.
    pub(in crate::sumeragi) fn from_view(
        state: &State,
        view: &StateView<'_>,
        generation: u64,
    ) -> Result<Option<Self>, Attempt<io::Error>> {
        if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        {
            return Err(pending("native State publication changed before history capture").into());
        }
        let kura = state.kura_handle();
        let budget = state.ivm_execution_budget();
        if !std::ptr::eq(view.ivm, &state.ivm)
            || !view
                .pipeline_ivm_prepared_cache
                .execution_budget()
                .same_pool(&budget)
            || !std::ptr::eq(view.kura(), kura.as_ref())
            || view.network_id() != state.network_id_ref()
            || view.chain_id() != state.chain_id_ref()
        {
            return Err(invalid("native history capture belongs to another original State").into());
        }
        if view.kura().native_consensus_gate().is_closed() {
            return Err(
                io::Error::other("native storage gate is closed; restart is required").into(),
            );
        }
        let Some(tip) = view.native_execution_tip() else {
            return Ok(None);
        };
        if tip.height() != view.height() as u64
            || Some(tip.iroha_hash()) != view.latest_block_hash()
        {
            return Err(invalid("native lane lookup has no matching original State tip").into());
        }
        if tip.height() < 2 {
            return Ok(None);
        }
        let policy = view
            .world()
            .sumeragi_npos_parameters()
            .map_err(|error| error.map_rejection(|message| invalid(&message)))?
            .map(|policy| {
                (
                    policy.evidence_horizon_blocks(),
                    policy.slashing_delay_blocks(),
                )
            });
        if !crate::state::is_stable_state_view_generation(generation, state.state_view_generation())
        {
            return Err(pending("native State publication changed during history capture").into());
        }
        Ok(Some(Self {
            generation,
            original_tip: tip,
            kura,
            budget,
            network: *view.network_id(),
            chain_id: view.chain_id().clone(),
            policy,
        }))
    }
}

pub(in crate::sumeragi) struct HistoryScan {
    lane: LaneId,
    incarnation: [u8; 32],
    generation: u64,
    height: u64,
    carrier: HashOf<BlockHeader>,
    original_tip: crate::state::NativeExecutionTip,
    kura: Arc<Kura>,
    archive: Option<NativeContextArchive>,
    read: Option<NativeContextRead>,
    budget: AllocationBudget,
    network: iroha_data_model::NetworkId,
    authority: Option<AuthorityRead>,
    tip_payload: Option<TipPayloadRead>,
    instance: iroha_sumeragi::types::Hash32,
    policy: Option<(u64, u64)>,
    verifier: NativeExecutionEvidenceVerifier,
    selected: LaneSelection,
    next: u64,
    current: Option<iroha_data_model::block::SharedSignedBlock>,
    current_bytes: Option<ChargedBuffer<u8>>,
    artifacts: Option<PrefixArtifactsRead>,
    genesis_bytes: Option<ChargedBuffer<u8>>,
    evidence_cut: Option<LaneEvidenceScope>,
    completed: bool,
    refusal: Option<crate::execution_attempt::ExecutionDeferred>,
}

impl HistoryScan {
    pub(super) fn open(
        state: &State,
        lane: LaneId,
        incarnation: [u8; 32],
    ) -> Result<Option<Self>, Attempt<io::Error>> {
        let generation = state.state_view_generation();
        if generation % 2 != 0 {
            return Err(pending("native State publication is in progress").into());
        }
        let capture = {
            let view = state.view();
            HistoryCapture::from_view(state, &view, generation)?
        };
        capture
            .map(|capture| {
                Self::open_captured(capture, lane, incarnation).map_err(|(_, error)| error)
            })
            .transpose()
    }

    /// The original World guard is gone before opening or reading any lane/global artifact.
    /// Opening failure returns the unchanged captured State cut and original pool.
    #[expect(
        clippy::result_large_err,
        reason = "return original capture without allocating on refusal"
    )]
    pub(in crate::sumeragi) fn open_captured(
        capture: HistoryCapture,
        lane: LaneId,
        incarnation: [u8; 32],
    ) -> Result<Self, (HistoryCapture, Attempt<io::Error>)> {
        let prepared: Result<_, Attempt<io::Error>> = (|| {
            let height = capture.original_tip.height();
            if height < 2 {
                return Err(invalid("native history requires a genesis/successor interval").into());
            }
            let state_bound = u64::try_from(capture.kura.native_context_archive_max_bytes().get())
                .map_err(invalid)?;
            let block_bound = MAX_FINALITY_BLOCK_BYTES as u64;
            let retained = block_bound
                .checked_add(state_bound)
                .and_then(|bytes| bytes.checked_mul(height))
                .ok_or_else(|| invalid("native authority history bound overflow"))?;
            let archive = NativeContextArchive::open_existing(
                &capture.kura,
                capture.budget.clone(),
                capture.kura.native_context_archive_max_bytes(),
            )
            .map_err(archive_error)?;
            let instance = crate::sumeragi::lanes::incarnation_instance(
                &crate::sumeragi::crypto::BlsCrypto::new(),
                &capture.network,
                capture.chain_id.as_str(),
                lane,
                &incarnation,
            );
            Ok((
                archive,
                instance,
                NativeExecutionEvidenceLimits {
                    max_carriers: height,
                    max_carrier_bytes: block_bound,
                    max_context_bytes: state_bound,
                    max_retained_bytes: retained,
                },
            ))
        })();
        let (archive, instance, limits) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err((capture, error)),
        };
        let HistoryCapture {
            generation,
            original_tip,
            kura,
            budget,
            network,
            chain_id,
            policy,
        } = capture;
        let height = original_tip.height();
        let carrier = original_tip.iroha_hash();
        // The checked positive bounds above admit at least two complete carriers and contexts.
        // No fallible opening remains after moving the original chain identity into its verifier.
        let verifier = NativeExecutionEvidenceVerifier::new(chain_id, network, limits)
            .expect("positive complete genesis/successor bounds checked before consuming capture");
        Ok(Self {
            lane,
            incarnation,
            generation,
            height,
            carrier,
            original_tip,
            kura,
            archive: Some(archive),
            read: None,
            budget,
            network,
            authority: None,
            tip_payload: None,
            instance,
            policy,
            verifier,
            selected: LaneSelection::new(lane, incarnation),
            next: 1,
            current: None,
            current_bytes: None,
            artifacts: None,
            genesis_bytes: None,
            evidence_cut: None,
            completed: false,
            refusal: None,
        })
    }

    /// Select a claimed original admission parent inside the independently captured prefix.
    /// The claim grants no authority: completion verifies all four identities and original row.
    #[expect(
        clippy::result_large_err,
        reason = "return original capture without allocating on refusal"
    )]
    pub(in crate::sumeragi) fn open_for_evidence(
        capture: HistoryCapture,
        scope: LaneEvidenceScope,
    ) -> Result<Self, (HistoryCapture, Attempt<io::Error>)> {
        if scope.admission_parent_height > capture.original_tip.height()
            || scope
                .created_at
                .checked_add(2)
                .is_none_or(|active| active > scope.admission_parent_height)
            || scope.admission_parent_height.checked_add(1).is_none()
        {
            return Err((
                capture,
                invalid("lane evidence parent is outside its original root lifetime").into(),
            ));
        }
        let mut scan = Self::open_captured(capture, scope.lane, scope.incarnation)?;
        scan.evidence_cut = Some(scope);
        Ok(scan)
    }

    fn selected_height(&self) -> u64 {
        self.evidence_cut
            .map_or(self.height, |scope| scope.admission_parent_height)
    }

    pub(super) fn matches(&self, lane: LaneId, incarnation: &[u8; 32]) -> bool {
        self.lane == lane && &self.incarnation == incarnation
    }

    pub(in crate::sumeragi) fn generation(&self) -> u64 {
        self.generation
    }

    // Local archive admission refusal leaves the verified prefix, selected original record,
    // exact current carrier and retained directory descriptor untouched for the next call.
    pub(in crate::sumeragi) fn complete(&mut self) -> Result<(), Attempt<io::Error>> {
        let result = self.progress().map_err(original_history_attempt);
        self.refusal = match &result {
            Err(Attempt::Deferred(original)) => Some(original.clone()),
            _ => None,
        };
        result
    }

    fn progress(&mut self) -> Result<(), Attempt<io::Error>> {
        self.completed = false;
        while self.next <= self.height {
            if self.current.is_none() {
                let index = usize::try_from(self.next)
                    .ok()
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| invalid("native carrier height overflow"))?;
                let block = self
                    .kura
                    .get_block(index, &self.budget)
                    .map_err(|error| error.map_rejection(io::Error::other))?
                    .ok_or_else(|| {
                        invalid("native carrier is missing from the captured committed prefix")
                    })?;
                let length = norito::canonical_frame_len(block.as_ref())
                    .map_err(invalid)?
                    .checked_add(1)
                    .ok_or_else(|| invalid("native carrier byte length overflow"))?;
                if length > MAX_FINALITY_BLOCK_BYTES {
                    return Err(
                        invalid("native carrier exceeds its independent reader bound").into(),
                    );
                }
                self.current = Some(block);
            }
            let block = self.current.as_ref().expect("retained original carrier");
            if self.next == self.height && block.hash() != self.carrier {
                return Err(
                    invalid("native authority prefix differs from captured State tip").into(),
                );
            }
            if self.evidence_cut.is_some_and(|scope| {
                self.next == scope.admission_parent_height
                    && block.hash() != scope.admission_parent_hash
            }) {
                return Err(invalid("lane evidence admission parent carrier differs").into());
            }
            if self.current_bytes.is_none() {
                if self.read.is_none() {
                    self.read = Some(
                        self.archive
                            .take()
                            .expect("original archive owner")
                            .read_job(self.next, block.hash()),
                    );
                }
                let bytes = loop {
                    match self.read.as_mut().expect("original acquisition").poll() {
                        Ok(Some(bytes)) => break bytes,
                        Ok(None) => {}
                        Err(NativeContextArchiveError::Io(error))
                            if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(archive_error(error)),
                    }
                };
                self.archive = Some(
                    self.read
                        .take()
                        .expect("completed acquisition")
                        .into_archive(),
                );
                self.current_bytes = Some(bytes);
            }
            // Large certificate fields and the exact proposal image acquire real owners
            // before verification can advance/poison its prefix. A refusal preserves both
            // archive bytes and partial artifact acquisition from this original carrier.
            let artifacts = if self.next > 1 {
                let read = self.artifacts.take().unwrap_or_else(|| {
                    PrefixArtifactsRead::new(Clone::clone(block), self.budget.clone())
                });
                match read.complete(&self.budget) {
                    Ok(artifacts) => Some(artifacts),
                    Err((read, error)) => {
                        self.artifacts = Some(read);
                        return Err(prefix_error(error));
                    }
                }
            } else {
                None
            };
            let bytes = self.current_bytes.take().expect("original context bytes");
            let selected_height = self.selected_height();
            let selected = &mut self.selected;
            let authority = &mut self.authority;
            let budget = &self.budget;
            let network = self.network;
            let genesis_bytes = &mut self.genesis_bytes;
            let accept_genesis = |genesis: crate::state::VerifiedNativeExecutionCarrier| {
                let bytes = genesis_bytes
                    .take()
                    .ok_or("original genesis archive owner is missing")?;
                if selected
                    .observe(1, genesis.lanes())
                    .map_err(|error| error.to_string())?
                {
                    *authority = Some(AuthorityRead::Payload(LanePayloadRead::from_verified(
                        bytes,
                        budget.clone(),
                        network,
                        &genesis,
                    )));
                }
                Ok(())
            };
            let receipt = match artifacts {
                Some(artifacts) => self.verifier.push_prepared_height_with_genesis(
                    artifacts,
                    bytes.as_slice(),
                    accept_genesis,
                ),
                None => self.verifier.push_shared_height_with_genesis(
                    Clone::clone(block),
                    bytes.as_slice(),
                    accept_genesis,
                ),
            }
            .map_err(invalid)?;
            if let Some(receipt) = receipt {
                if self.next == self.height && !receipt.matches_original_tip(self.original_tip) {
                    return Err(invalid(
                        "verified authority prefix differs from original native execution result",
                    )
                    .into());
                }
                if let Some(scope) = self.evidence_cut
                    && self.next == scope.admission_parent_height
                    && !receipt.matches_claimed_cut(
                        scope.admission_parent_height,
                        scope.admission_parent_hash,
                        iroha_sumeragi::types::Hash32(scope.admission_parent_core_hash),
                        iroha_sumeragi::types::Hash32(scope.admission_parent_result),
                    )
                {
                    return Err(invalid(
                        "lane evidence parent differs from its original execution",
                    )
                    .into());
                }
                if selected.observe(receipt.block().header().height().get(), receipt.lanes())? {
                    *authority = Some(AuthorityRead::Payload(LanePayloadRead::from_verified(
                        bytes,
                        budget.clone(),
                        network,
                        &receipt,
                    )));
                } else if self.next == selected_height {
                    self.tip_payload = Some(TipPayloadRead::Pending(
                        LanePayloadRead::from_verified(bytes, budget.clone(), network, &receipt),
                    ));
                }
            } else {
                *genesis_bytes = Some(bytes);
            }
            self.current = None;
            self.next = self
                .next
                .checked_add(1)
                .ok_or_else(|| invalid("native authority height exhausted"))?;
        }
        self.archive
            .as_ref()
            .expect("complete namespace")
            .recheck_namespace()
            .map_err(archive_error)?;
        if !self.selected.is_active(self.selected_height()) {
            self.authority = None;
            self.completed = true;
            return Ok(());
        }
        if matches!(self.tip_payload, Some(TipPayloadRead::Pending(_))) {
            let Some(TipPayloadRead::Pending(read)) = self.tip_payload.take() else {
                unreachable!("checked pending original payload")
            };
            match read.authenticate() {
                Ok(payload) => self.tip_payload = Some(TipPayloadRead::Ready(payload)),
                Err((read, error)) => {
                    self.tip_payload = Some(TipPayloadRead::Pending(read));
                    return Err(payload_error(error));
                }
            }
        }
        loop {
            match self.authority.take().expect("selected original creation") {
                AuthorityRead::Payload(read) => match read.authenticate() {
                    Ok(source) => {
                        self.authority = Some(AuthorityRead::Config(LaneAuthorityRead::new(
                            source,
                            self.incarnation,
                        )))
                    }
                    Err((read, error)) => {
                        self.authority = Some(AuthorityRead::Payload(read));
                        return Err(payload_error(error));
                    }
                },
                AuthorityRead::Config(read) => match read.complete(&self.budget) {
                    Ok(owner) => self.authority = Some(AuthorityRead::Ready(owner)),
                    Err((read, error)) => {
                        self.authority = Some(AuthorityRead::Config(read));
                        return Err(payload_error(error));
                    }
                },
                AuthorityRead::Ready(owner) => {
                    let validation = match &self.tip_payload {
                        Some(TipPayloadRead::Ready(payload)) => owner.validate_custody(
                            payload,
                            self.instance,
                            self.policy,
                            &self.budget,
                        ),
                        _ => Err(LanePayloadError::Source),
                    };
                    self.authority = Some(AuthorityRead::Ready(owner));
                    validation.map_err(payload_error)?;
                    self.archive
                        .as_ref()
                        .expect("same completed namespace")
                        .recheck_namespace()
                        .map_err(archive_error)?;
                    self.completed = true;
                    return Ok(());
                }
            }
        }
    }

    pub(super) fn finish(self) -> Option<LaneAuthority> {
        if !self.completed {
            return None;
        }
        match self.authority {
            Some(AuthorityRead::Ready(owner)) => Some(owner),
            _ => None,
        }
    }
}

/// A complete original global prefix and its selected original lane admission context.
/// Retaining this value keeps both source payloads and the prepaid configuration alive.
pub(in crate::sumeragi) struct LaneEvidenceContext {
    pub(in crate::sumeragi) authority: LaneAuthority,
    pub(in crate::sumeragi) payload: LanePayload,
    pub(in crate::sumeragi) scope: LaneEvidenceScope,
    pub(in crate::sumeragi) instance: iroha_sumeragi::types::Hash32,
    pub(in crate::sumeragi) original_tip: crate::state::NativeExecutionTip,
    pub(in crate::sumeragi) generation: u64,
    pub(in crate::sumeragi) network: iroha_data_model::NetworkId,
    pub(in crate::sumeragi) budget: AllocationBudget,
    pub(in crate::sumeragi) kura: Arc<Kura>,
}
impl HistoryScan {
    /// Validate the complete borrowed handoff before moving any original funded owner.
    /// Zero-copy field inspection still observes the ambient decoder field ceiling.
    fn validate_evidence_completion(&self) -> Result<(), Attempt<io::Error>> {
        if !self.completed {
            return Err(invalid("lane evidence history has not completed authentication").into());
        }
        let scope = self
            .evidence_cut
            .ok_or_else(|| invalid("missing original evidence cut"))?;
        let Some(AuthorityRead::Ready(authority)) = self.authority.as_ref() else {
            return Err(invalid("original lane was not active at evidence admission").into());
        };
        let Some(TipPayloadRead::Ready(payload)) = self.tip_payload.as_ref() else {
            return Err(invalid("original admission payload is missing").into());
        };
        if authority.created_at() != scope.created_at {
            return Err(invalid("lane evidence creation differs from original authority").into());
        }
        let row = payload
            .custody_record(&scope.incarnation)
            .map_err(payload_error)?
            .ok_or_else(|| invalid("lane evidence has no original custody obligation"))?;
        if row.identity()
            != (
                scope.lane,
                scope.incarnation,
                self.instance.0,
                scope.created_at,
            )
            || !row
                .admits_at(
                    scope
                        .admission_parent_height
                        .checked_add(1)
                        .ok_or_else(|| invalid("lane evidence carrier height overflows"))?,
                )
                .map_err(payload_error)?
        {
            return Err(invalid(
                "lane evidence admission is outside its original custody lifetime",
            )
            .into());
        }
        Ok(())
    }

    /// Return the original completed history owner whenever handoff refuses locally.
    #[expect(
        clippy::result_large_err,
        reason = "return the original funded history without allocating on refusal"
    )]
    pub(in crate::sumeragi) fn finish_evidence(
        self,
    ) -> Result<LaneEvidenceContext, (Self, Attempt<io::Error>)> {
        if let Err(error) = self.validate_evidence_completion() {
            return Err((self, original_history_attempt(error)));
        }
        let scope = self.evidence_cut.expect("validated original evidence cut");
        let Some(AuthorityRead::Ready(authority)) = self.authority else {
            unreachable!("validated original authority")
        };
        let Some(TipPayloadRead::Ready(payload)) = self.tip_payload else {
            unreachable!("validated original payload")
        };
        Ok(LaneEvidenceContext {
            authority,
            payload,
            scope,
            instance: self.instance,
            original_tip: self.original_tip,
            generation: self.generation,
            network: self.network,
            budget: self.budget,
            kura: self.kura,
        })
    }
}

// The compiled mutation restores the original erased producer outcome without injecting
// faults into a configured node. Normal attempts move the exact original retry owner.
fn original_history_attempt(error: Attempt<io::Error>) -> Attempt<io::Error> {
    if cfg!(all(test, sumeragi_core_mutation = "HC51")) && matches!(error, Attempt::Deferred(_)) {
        return io::Error::from(io::ErrorKind::WouldBlock).into();
    }
    error
}

/// Retain the original local attempt before either history consumer constructs a diagnostic.
pub(in crate::sumeragi) fn payload_error(error: LanePayloadError) -> Attempt<io::Error> {
    let error = match error {
        LanePayloadError::Codec(error) => {
            return norito_decode_attempt_error(error, |error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            });
        }
        LanePayloadError::Proof(
            iroha_data_model::sumeragi_finality::NativeLaneStateProofError::Decode(original),
        ) => {
            return canonical_decode_attempt_error(original, |error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            });
        }
        error => error,
    };
    if !error.is_local_refusal() {
        return io::Error::new(io::ErrorKind::InvalidData, error).into();
    }
    match error {
        LanePayloadError::Admission(refusal) => Attempt::Deferred(refusal.into()),
        LanePayloadError::Materialization(iroha_allocation::PrepaidBufferError::Allocation(
            error,
        ))
        | LanePayloadError::Proof(
            iroha_data_model::sumeragi_finality::NativeLaneStateProofError::Scratch(error),
        ) => crate::sumeragi::storage_attempt::buffer(error),
        error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
    }
}

fn archive_error(error: NativeContextArchiveError) -> Attempt<io::Error> {
    let local = error.is_local_refusal();
    match error {
        NativeContextArchiveError::Allocation(error) if local => {
            crate::sumeragi::storage_attempt::buffer(error)
        }
        NativeContextArchiveError::Proof(
            iroha_data_model::sumeragi_finality::NativeLaneStateProofError::Decode(original),
        ) => canonical_decode_attempt_error(original, |error| {
            io::Error::new(io::ErrorKind::InvalidData, error)
        }),
        NativeContextArchiveError::Proof(
            iroha_data_model::sumeragi_finality::NativeLaneStateProofError::Scratch(original),
        ) if local => crate::sumeragi::storage_attempt::buffer(original),
        NativeContextArchiveError::Codec(error) => norito_decode_attempt_error(error, |error| {
            io::Error::new(io::ErrorKind::InvalidData, error)
        }),
        NativeContextArchiveError::Io(error) => error.into(),
        error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
    }
}

fn prefix_error(error: PrefixArtifactsError) -> Attempt<io::Error> {
    match error {
        PrefixArtifactsError::Certificate(CertificateReadError::Admission(error))
        | PrefixArtifactsError::Projection(PayloadBuildError::Admission(error))
            if error.is_local_refusal() =>
        {
            crate::sumeragi::storage_attempt::byte(error)
        }
        PrefixArtifactsError::Certificate(CertificateReadError::Decode(error)) => {
            norito_decode_attempt_error(error, |error| {
                io::Error::new(io::ErrorKind::InvalidData, error)
            })
        }
        error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::{AllocationBudget, ChargedBuffer};

    #[test]
    fn archive_allocation_refusal_remains_retryable_without_diagnostic_allocation() {
        let budget = AllocationBudget::new(1);
        let held = ChargedBuffer::<u8>::new(1, &budget).unwrap();
        for requested in [1, 2] {
            let refused = ChargedBuffer::<u8>::new(requested, &budget).err().unwrap();
            let mapped = archive_error(NativeContextArchiveError::Allocation(refused));
            assert_eq!(mapped.io_kind(), io::ErrorKind::WouldBlock);
            assert!(matches!(mapped, Attempt::Deferred(_)));
            assert_eq!(budget.reserved_bytes(), 1);
        }
        let physical = archive_error(NativeContextArchiveError::Allocation(
            iroha_allocation::ChargedBufferError::Allocator { requested_bytes: 1 },
        ));
        assert_eq!(physical.io_kind(), io::ErrorKind::WouldBlock);
        assert!(matches!(physical, Attempt::Deferred(_)));
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn payload_refusal_avoids_diagnostic_allocation_but_source_errors_remain_typed() {
        let budget = AllocationBudget::new(1);
        let held = ChargedBuffer::<u8>::new(1, &budget).unwrap();
        for requested in [1, 2] {
            let refused = budget.try_reserve_bytes(requested).err().unwrap();
            let mapped = payload_error(LanePayloadError::Admission(refused));
            assert_eq!(mapped.io_kind(), io::ErrorKind::WouldBlock);
            assert!(matches!(mapped, Attempt::Deferred(_)));
            assert_eq!(budget.reserved_bytes(), 1);
        }
        let physical = payload_error(LanePayloadError::Materialization(
            iroha_allocation::PrepaidBufferError::Allocation(
                iroha_allocation::ChargedBufferError::Allocator { requested_bytes: 1 },
            ),
        ));
        assert_eq!(physical.io_kind(), io::ErrorKind::WouldBlock);
        assert!(matches!(physical, Attempt::Deferred(_)));
        for error in [LanePayloadError::Source, LanePayloadError::Commitment] {
            let mapped = payload_error(error);
            assert_eq!(mapped.io_kind(), io::ErrorKind::InvalidData);
            assert!(
                matches!(&mapped, Attempt::Rejected(error) if error.get_ref().unwrap().is::<LanePayloadError>())
            );
        }
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn missing_archive_and_malformed_source_are_not_absence_or_capacity_refusal() {
        let io = archive_error(NativeContextArchiveError::Io(
            std::io::Error::from(std::io::ErrorKind::NotFound).into(),
        ));
        assert_eq!(io.io_kind(), io::ErrorKind::NotFound);
        for error in [
            NativeContextArchiveError::Source("substituted archive"),
            NativeContextArchiveError::Limit {
                maximum: 16,
                actual: 17,
            },
        ] {
            let mapped = archive_error(error);
            assert_eq!(mapped.io_kind(), io::ErrorKind::InvalidData);
            assert!(
                matches!(&mapped, Attempt::Rejected(error) if error.get_ref().unwrap().is::<NativeContextArchiveError>())
            );
        }
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;

    #[test]
    fn certificate_refusal_keeps_completed_archive_and_prefix_until_original_retry() {
        let (chain, record, _epoch) = super::super::tests::fixed_lane_chain();
        let budget = chain.state().ivm_execution_budget();
        let before = budget.reserved_bytes();
        let limit = budget.limit_bytes();
        let mut scan = HistoryScan::open(chain.state(), record.lane, record.incarnation)
            .unwrap()
            .unwrap();
        // Complete the exact H1 trust-root phase. H1 still grants no execution authority;
        // H2 must authenticate it after acquiring its original bulk certificate artifacts.
        let genesis = chain
            .kura()
            .get_block(
                NonZeroUsize::new(1).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .expect("original block read attempt")
            .unwrap();
        let archive = scan.archive.as_ref().unwrap();
        let genesis_bytes = archive.read_exact(1, genesis.hash()).unwrap();
        assert!(
            scan.verifier
                .push_height(Clone::clone(&genesis), genesis_bytes.as_slice())
                .unwrap()
                .is_none()
        );
        scan.genesis_bytes = Some(genesis_bytes);
        scan.next = 2;
        let block = chain
            .kura()
            .get_block(
                NonZeroUsize::new(2).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .expect("original block read attempt")
            .unwrap();
        scan.current_bytes = Some(archive.read_exact(2, block.hash()).unwrap());
        let bytes = scan.current_bytes.as_ref().unwrap().as_slice().as_ptr();
        scan.current = Some(Clone::clone(&block));
        // The fixture pin retains only retired State generations. The reader's table,
        // proposal and shared-control owners still refund immediately while it is live.
        let artifact_baseline = budget.reserved_bytes();
        let artifacts = PrefixArtifactsRead::new(Clone::clone(&block), budget.clone())
            .complete(&budget)
            .unwrap_or_else(|(_, error)| panic!("original artifacts: {error}"));
        assert!(budget.reserved_bytes() > artifact_baseline);
        drop(artifacts);
        assert_eq!(budget.reserved_bytes(), artifact_baseline);
        budget.set_limit_bytes(budget.reserved_bytes());
        let error = scan.complete().unwrap_err();
        assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
        assert!(
            matches!(error, Attempt::Deferred(_)),
            "local refusal has no diagnostic box"
        );
        assert_eq!(scan.next, 2);
        assert!(scan.artifacts.is_some());
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            scan.current.as_ref().unwrap(),
            &block
        ));
        assert_eq!(
            scan.current_bytes.as_ref().unwrap().as_slice().as_ptr(),
            bytes
        );
        assert_eq!(
            scan.complete().unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            scan.current_bytes.as_ref().unwrap().as_slice().as_ptr(),
            bytes
        );
        // A fresh name now denotes corrupt bytes. This pending acquisition already owns
        // complete original bytes and must never use the replacement as its retry source.
        let path = chain
            .kura()
            .store_root()
            .join("native-contexts")
            .join(format!(
                "{:020}-{}.nrt",
                2,
                hex::encode(block.hash().as_ref()),
            ));
        let held = path.with_extension("original-artifact-retry");
        std::fs::rename(&path, &held).unwrap();
        std::fs::write(&path, b"replacement must not become pending source").unwrap();
        budget.set_limit_bytes(limit);
        scan.complete().unwrap();
        assert!(scan.next > scan.height);
        let owner = scan.finish().expect("same original full prefix completes");
        assert!(owner.belongs_to(&budget));
        drop(owner);
        assert_eq!(budget.reserved_bytes(), before);
        let mut fresh = HistoryScan::open(chain.state(), record.lane, record.incarnation)
            .unwrap()
            .unwrap();
        assert!(
            fresh.complete().is_err(),
            "fresh acquisition rejects replaced source"
        );
        drop(fresh);
        assert_eq!(budget.reserved_bytes(), before);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(held, path).unwrap();
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    #[test]
    fn original_cut_capture_does_not_open_the_archive_and_never_upgrades_to_a_successor() {
        let (mut chain, record, _epoch) = super::super::tests::fixed_lane_chain();
        let state = Clone::clone(chain.state());
        let generation = state.state_view_generation();
        let view = state.view();
        let original = view.native_execution_tip().unwrap();
        let path = chain.kura().store_root().join("native-contexts");
        let held = path.with_extension("capture-held");
        std::fs::rename(&path, &held).unwrap();
        let captured = HistoryCapture::from_view(&state, &view, generation)
            .unwrap()
            .unwrap();
        assert_eq!(captured.original_tip, original);
        std::fs::rename(&held, &path).unwrap();
        drop(view);
        chain.commit(Vec::new());
        assert_ne!(state.state_view_generation(), generation);
        let budget = state.ivm_execution_budget();
        let baseline = budget.reserved_bytes();
        let mut read =
            HistoryScan::open_captured(captured, record.lane, record.incarnation).unwrap();
        read.complete().unwrap();
        assert_eq!(read.original_tip, original);
        assert_eq!(read.height, original.height());
        assert_eq!(read.generation(), generation);
        assert!(!crate::state::is_stable_state_view_generation(
            read.generation(),
            state.state_view_generation()
        ));
        let Some(TipPayloadRead::Ready(payload)) = &read.tip_payload else {
            panic!("exact original payload");
        };
        assert_eq!(payload.carrier().1, original.height());
        assert_eq!(payload.carrier().2, original.iroha_hash());
        drop(read);
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    #[test]
    fn foreign_state_or_stale_generation_cannot_create_an_original_history_capture() {
        let (chain, _, _epoch) = super::super::tests::fixed_lane_chain();
        let (other, _, _other_epoch) = super::super::tests::fixed_lane_chain();
        let view = chain.state().view();
        let generation = chain.state().state_view_generation();
        for invalid in [generation | 1, generation.checked_add(2).unwrap()] {
            assert_eq!(
                HistoryCapture::from_view(chain.state(), &view, invalid)
                    .err()
                    .unwrap()
                    .io_kind(),
                io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(
            HistoryCapture::from_view(other.state(), &view, other.state().state_view_generation())
                .err()
                .unwrap()
                .io_kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn original_capture_rejects_another_state_even_with_the_same_storage_and_identity() {
        use crate::{query::store::LiveQueryStore, state::World};
        let (chain, _, _epoch) = super::super::tests::fixed_lane_chain();
        let state = chain.state();
        let other = State::new_with_chain_and_network_id_for_testing(
            World::new(),
            Clone::clone(chain.kura()),
            LiveQueryStore::start_test(),
            state.chain_id_ref().clone(),
            chain.network_id(),
        );
        let view = state.view();
        assert!(std::ptr::eq(view.kura(), other.kura()));
        assert_eq!(view.network_id(), other.network_id_ref());
        assert_eq!(view.chain_id(), other.chain_id_ref());
        assert_eq!(
            HistoryCapture::from_view(&other, &view, other.state_view_generation())
                .err()
                .unwrap()
                .io_kind(),
            io::ErrorKind::InvalidData,
        );
        let mut view = state.view();
        view.pipeline_ivm_prepared_cache = other.view().pipeline_ivm_prepared_cache.clone();
        assert!(std::ptr::eq(view.ivm, &state.ivm));
        assert!(
            !view
                .pipeline_ivm_prepared_cache
                .execution_budget()
                .same_pool(&state.ivm_execution_budget())
        );
        assert_eq!(
            HistoryCapture::from_view(state, &view, state.state_view_generation())
                .err()
                .unwrap()
                .io_kind(),
            io::ErrorKind::InvalidData,
        );
    }
}

#[cfg(test)]
mod evidence_cut_tests {
    use super::*;
    use iroha_data_model::sumeragi_lanes::SumeragiLaneRecord;
    use iroha_sumeragi::types::Hash32;

    fn scope(
        record: &SumeragiLaneRecord,
        tip: crate::state::NativeExecutionTip,
    ) -> LaneEvidenceScope {
        LaneEvidenceScope {
            lane: record.lane,
            incarnation: record.incarnation,
            created_at: record.created_at,
            admission_parent_height: tip.height(),
            admission_parent_hash: tip.iroha_hash(),
            admission_parent_core_hash: tip.core_hash().0,
            admission_parent_result: tip.result().0,
        }
    }

    fn capture(state: &State) -> HistoryCapture {
        let generation = state.state_view_generation();
        HistoryCapture::from_view(state, &state.view(), generation)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn original_lane_admission_cut_survives_successor_publication_without_changing_its_pool() {
        let (mut chain, record, _epoch) = super::super::tests::npos_fixed_lane_chain_at(3);
        let original = chain.state().view().native_execution_tip().unwrap();
        let claim = scope(&record, original);
        chain.commit(Vec::new());
        let state = chain.state();
        let current = state.view().native_execution_tip().unwrap();
        assert!(current.height() > claim.admission_parent_height);
        let budget = state.ivm_execution_budget();
        let baseline = budget.reserved_bytes();
        let mut read = HistoryScan::open_for_evidence(capture(state), claim).unwrap();
        read.complete().unwrap();
        let context = read
            .finish_evidence()
            .unwrap_or_else(|(_, error)| panic!("{error}"));
        assert_eq!(context.scope, claim);
        assert_eq!(context.original_tip, current);
        assert_eq!(context.payload.carrier().1, original.height());
        assert_eq!(context.payload.carrier().2, original.iroha_hash());
        assert_eq!(
            context.authority.demotion_window(),
            record.params.demotion_window.get()
        );
        assert_eq!(context.authority.created_at(), record.created_at);
        assert!(context.authority.belongs_to(&budget));
        assert!(context.payload.belongs_to(&budget));
        assert!(context.budget.same_pool(&budget));
        assert!(Arc::ptr_eq(&context.kura, &state.kura_handle()));
        assert_eq!(context.network, *state.network_id_ref());
        assert_eq!(context.generation, state.state_view_generation());
        let row = context
            .payload
            .custody_record(&claim.incarnation)
            .unwrap()
            .unwrap();
        assert_eq!(
            row.identity(),
            (
                claim.lane,
                claim.incarnation,
                context.instance.0,
                claim.created_at
            )
        );
        assert!(row.admits_at(original.height() + 1).unwrap());
        assert_eq!(
            row.binding(0).unwrap(),
            None,
            "unfunded fixed signer remains forensic-only"
        );
        drop(context);
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    #[test]
    fn claimed_lane_cut_cannot_substitute_carrier_result_creation_or_future_height() {
        let (mut chain, record, _epoch) = super::super::tests::npos_fixed_lane_chain_at(4);
        let original = chain.state().view().native_execution_tip().unwrap();
        let claim = scope(&record, original);
        chain.commit(Vec::new());
        let current = chain.state().view().native_execution_tip().unwrap();
        let mut changed = claim;
        changed.admission_parent_hash = current.iroha_hash();
        let mut claims = vec![changed];
        changed = claim;
        changed.admission_parent_core_hash = Hash32([0x98; 32]).0;
        claims.push(changed);
        changed = claim;
        changed.admission_parent_result = Hash32([0x99; 32]).0;
        claims.push(changed);
        changed = claim;
        changed.created_at += 1;
        claims.push(changed);
        changed = claim;
        changed.admission_parent_height = current.height() + 1;
        claims.push(changed);
        for claim in claims {
            let result = HistoryScan::open_for_evidence(capture(chain.state()), claim);
            match result {
                Err((_, error)) => assert_eq!(error.io_kind(), io::ErrorKind::InvalidData),
                Ok(mut read) => {
                    if let Err(error) = read.complete() {
                        assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
                    }
                    assert!(read.finish_evidence().is_err());
                }
            }
        }
    }

    #[test]
    fn historical_store_authority_without_positive_policy_cannot_grant_evidence_custody() {
        let (chain, record, _epoch) = super::super::tests::fixed_lane_chain();
        let claim = scope(
            &record,
            chain.state().view().native_execution_tip().unwrap(),
        );
        let mut read = HistoryScan::open_for_evidence(capture(chain.state()), claim).unwrap();
        read.complete().unwrap();
        assert_eq!(
            read.finish_evidence().err().unwrap().1.io_kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn failed_custody_validation_cannot_extract_prepared_configuration() {
        let (chain, record, _epoch) = super::super::tests::npos_fixed_lane_chain_at(4);
        let claim = scope(
            &record,
            chain.state().view().native_execution_tip().unwrap(),
        );
        let mut read = HistoryScan::open_for_evidence(capture(chain.state()), claim).unwrap();
        read.complete().unwrap();
        assert!(matches!(read.authority, Some(AuthorityRead::Ready(_))));
        // A ready graph alone is not a completed capability: a rejected policy or final
        // namespace check must revoke completion before a consuming call can extract it.
        read.policy = None;
        assert_eq!(
            read.complete().unwrap_err().io_kind(),
            io::ErrorKind::InvalidData
        );
        assert!(read.finish().is_none());
    }

    #[test]
    fn original_cut_refusal_retains_job_and_completion_is_unavailable_until_retry() {
        let (chain, record, _epoch) = super::super::tests::npos_fixed_lane_chain_at(4);
        let state = chain.state();
        let claim = scope(&record, state.view().native_execution_tip().unwrap());
        let budget = state.ivm_execution_budget();
        let baseline = budget.reserved_bytes();
        let limit = budget.limit_bytes();
        let mut read = HistoryScan::open_for_evidence(capture(state), claim).unwrap();
        budget.set_limit_bytes(budget.reserved_bytes());
        assert_eq!(
            read.complete().unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!read.completed);
        assert_eq!(read.evidence_cut, Some(claim));
        assert_eq!(read.next, 1);
        assert!(read.read.is_some());
        budget.set_limit_bytes(limit);
        read.complete().unwrap();
        let context = read
            .finish_evidence()
            .unwrap_or_else(|(_, error)| panic!("{error}"));
        assert_eq!(context.scope, claim);
        drop(context);
        assert_eq!(budget.reserved_bytes(), baseline);
    }
}
