//! Original-history discovery for Begin, Prepared and multi-participant Decision delivery.
//!
//! An authenticated zero-record witness advances without an `.ami` file. A positive count
//! requires the exact complete scalar frame and original per-record authentication. Begin
//! rows retain discovery coordinates; Decision delivery never depends on current unpruned
//! AMX entries, a successor block, an independent file index or a second outbound journal.

use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, consensus::SumeragiRootScope},
    sumeragi_amx::{
        AMX_RECORD_WITNESS_KEY_BYTES, AllocatedAmxRecordProofV1, AmxRecordKind, AmxRecordV1,
        MAX_AMX_PARTICIPANTS,
    },
};
use iroha_model_base::topology::DataSpaceId;

use super::{
    NativeAmxBeginRelayErrorV1, NativeAmxBeginRelayPollV1, NativeAmxBeginRelayReadV1,
    NativeAmxDecisionRelayErrorV1, NativeAmxDecisionRelayPollV1, NativeAmxDecisionRelayReadV1,
    NativeAmxPreparedRelayErrorV1, NativeAmxPreparedRelayPollV1, NativeAmxPreparedRelayReadV1,
    NativeAmxRecordProofPollV1, NativeAmxRecordProofReadV1, NativeAmxRelayIntentV1,
    amx_intents::record_hash, amx_record_proof, begin_amx_relay, decision_amx_relay,
    prepared_amx_relays,
};
use crate::{
    query::native_context_archive::{
        NativeContextArchive, NativeContextRead,
        prepared_intents::{IntentProjection, Row},
    },
    state::StateReadOnly,
};

/// Original source or delivery refusal. No error acknowledges or advances pending work.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxRelayDiscoveryErrorV1 {
    /// The original complete witness, archive frame or Prepared instruction refused.
    #[error(transparent)]
    Source(#[from] NativeAmxPreparedRelayErrorV1),
    /// The original successful Begin input or Prepare instruction refused.
    #[error(transparent)]
    Begin(#[from] NativeAmxBeginRelayErrorV1),
    /// The original Begin/Decision join or Settle instruction refused.
    #[error(transparent)]
    Decision(#[from] NativeAmxDecisionRelayErrorV1),
}

/// One bounded source step, one move-only delivery, or exhaustion of the original height.
#[derive(Debug)]
pub enum NativeAmxRelayDiscoveryPollV1 {
    /// The same original sources made progress without delivering an instruction.
    Pending,
    /// Authenticated original instruction ready for separately configured custody and fees.
    Relay(NativeAmxRelayIntentV1),
    /// Every relevant original record was processed, including genuine zero-record blocks.
    Complete,
}

/// Bounded original-history discovery, retaining all pending jobs through refusal.
///
/// Keep the captured immutable authenticated State view alive. Restart reconstructs discovery
/// from the same canonical history; outbound exact-byte recovery uses the existing workflow
/// journal. Delivery of a Decision is not evidence of successful participant settlement.
#[must_use = "retain the original discovery job through refusal or explicitly retire it"]
pub struct NativeAmxRelayDiscoveryReadV1<'v, V: StateReadOnly> {
    instruction: Option<NativeAmxRelayIntentV1>,
    probe: Option<AllocatedAmxRecordProofV1>,
    prepare: Option<NativeAmxBeginRelayReadV1<'v, V>>,
    decision: Option<NativeAmxDecisionRelayReadV1<'v, V>>,
    begin: Option<NativeAmxRecordProofReadV1<'v, V>>,
    selected: Option<NativeAmxRecordProofReadV1<'v, V>>,
    prepared: Option<NativeAmxPreparedRelayReadV1<'v, V>>,
    source: NativeAmxRecordProofReadV1<'v, V>,
    bytes: Option<ChargedBuffer<u8>>,
    read: NativeContextRead,
    projection: Option<IntentProjection>,
    row: Option<(Row, usize)>,
    previous: Option<[u8; AMX_RECORD_WITNESS_KEY_BYTES]>,
    participants: [DataSpaceId; MAX_AMX_PARTICIPANTS],
    participants_len: usize,
    participant_index: usize,
    count: Option<usize>,
    index: usize,
    offset: usize,
    selected_verified: bool,
    complete: bool,
    scope: SumeragiRootScope,
    height: u64,
    carrier: HashOf<BlockHeader>,
    view: &'v V,
    budget: AllocationBudget,
}

/// Discover relay work at an exact certified height, including a final tip with no successor.
///
/// The all-zero record selector below only drives complete witness verification; neither
/// presence nor absence of that selected record establishes the source's authority.
///
/// # Errors
/// The height is outside authenticated non-genesis history or its original archive refuses.
pub fn amx_relays<V: StateReadOnly>(
    view: &V,
    height: u64,
) -> Result<NativeAmxRelayDiscoveryReadV1<'_, V>, NativeAmxRelayDiscoveryErrorV1> {
    use NativeAmxPreparedRelayErrorV1 as Error;
    let index = height
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
        .filter(|_| height >= 2)
        .ok_or(Error::Source("relay discovery needs non-genesis history"))?;
    let carrier = view
        .block_hashes()
        .get(index)
        .copied()
        .ok_or(Error::Source(
            "relay discovery height is outside captured history",
        ))?;
    let scope = view
        .native_execution_tip()
        .map(|tip| tip.root_scope())
        .ok_or(Error::Source(
            "relay discovery requires authenticated root scope",
        ))?;
    let budget = view.prepared_contract_cache().execution_budget().clone();
    let archive = NativeContextArchive::open_existing(
        view.kura(),
        budget.clone(),
        view.kura().native_context_archive_max_bytes(),
    )
    .map_err(Error::Archive)?;
    Ok(NativeAmxRelayDiscoveryReadV1 {
        instruction: None,
        probe: None,
        prepare: None,
        decision: None,
        begin: None,
        selected: None,
        prepared: None,
        source: amx_record_proof(view, height, AmxRecordKind::Prepared, [0; 32]),
        bytes: None,
        read: archive.prepared_intent_read_job(height, carrier),
        projection: None,
        row: None,
        previous: None,
        participants: [DataSpaceId::UNIVERSAL; MAX_AMX_PARTICIPANTS],
        participants_len: 0,
        participant_index: 0,
        count: None,
        index: 0,
        offset: 0,
        selected_verified: false,
        complete: false,
        scope,
        height,
        carrier,
        view,
        budget,
    })
}

impl<V: StateReadOnly> NativeAmxRelayDiscoveryReadV1<'_, V> {
    fn recheck(&self) -> Result<(), NativeAmxPreparedRelayErrorV1> {
        use NativeAmxPreparedRelayErrorV1 as Error;
        self.read.recheck_namespace()?;
        let index = usize::try_from(self.height - 1)
            .map_err(|_| Error::Source("height exceeds address space"))?;
        if self.view.block_hashes().get(index).copied() != Some(self.carrier)
            || self.view.native_execution_tip().map(|tip| tip.root_scope()) != Some(self.scope)
            || self
                .bytes
                .as_ref()
                .is_some_and(|bytes| !bytes.belongs_to(&self.budget))
        {
            return Err(Error::Source(
                "relay discovery lost original history or pool",
            ));
        }
        if self.count.is_some() {
            let source = self.source.completed_original()?;
            if source.block_hash() != self.carrier || source.root_scope() != self.scope {
                return Err(Error::Source(
                    "relay discovery differs from original certified root",
                ));
            }
        }
        if let Some(projection) = &self.projection {
            if !projection.matches_root(
                self.bytes.as_ref().expect("original frame").as_slice(),
                self.view,
                self.height,
                self.carrier,
            ) || !self
                .source
                .matches_completed_execution(self.carrier, projection.ordinary_writes_root)
            {
                return Err(Error::Source(
                    "relay discovery frame differs from original certified execution",
                ));
            }
        }
        Ok(())
    }
    fn finish_row(&mut self) {
        let (row, next) = self.row.take().expect("verified original row");
        self.previous = Some(row.key);
        self.offset = next;
        self.index += 1;
        // These are explicitly retired selector probes, never reconstructed proof authority.
        self.selected = None;
        self.begin = None;
        self.decision = None;
        self.prepare = None;
        self.selected_verified = false;
        self.participants_len = 0;
        self.participant_index = 0;
    }
    /// Make bounded progress without dropping original sources after a refusal.
    ///
    /// # Errors
    /// Exact original source, decoder or instruction refusal; no pending row advances.
    pub fn poll(
        &mut self,
    ) -> Result<NativeAmxRelayDiscoveryPollV1, NativeAmxRelayDiscoveryErrorV1> {
        use NativeAmxPreparedRelayErrorV1 as Error;
        use NativeAmxRelayDiscoveryPollV1 as Poll;
        if self.complete {
            return Err(Error::Source("relay discovery already completed").into());
        }
        self.recheck()?;
        if self.count.is_none() {
            match self.source.poll().map_err(Error::Proof)? {
                NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                NativeAmxRecordProofPollV1::Complete(probe) => {
                    // The exact all-zero selection has no delivery role, even if present.
                    drop(probe);
                    self.count = Some(
                        self.source
                            .authenticated_relay_record_count()
                            .map_err(Error::Proof)?,
                    );
                }
            }
            self.recheck()?;
            return Ok(Poll::Pending);
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC270")))]
        if self.count == Some(0) {
            self.complete = true;
            return Ok(Poll::Complete);
        }
        if self.prepared.is_none() && matches!(self.scope, SumeragiRootScope::Dataspace { .. }) {
            self.prepared = Some(prepared_amx_relays(self.view, self.height)?);
        }
        if let Some(prepared) = &mut self.prepared {
            return Ok(match prepared.poll()? {
                NativeAmxPreparedRelayPollV1::Pending => Poll::Pending,
                NativeAmxPreparedRelayPollV1::Relay(intent) => Poll::Relay(intent),
                NativeAmxPreparedRelayPollV1::Complete => {
                    self.complete = true;
                    Poll::Complete
                }
            });
        }
        if self.bytes.is_none() {
            self.bytes = self.read.poll().map_err(Error::Archive)?;
            return Ok(Poll::Pending);
        }
        let bytes = self.bytes.as_ref().expect("original frame");
        if self.projection.is_none() {
            let projection = norito::core::classify_decode_attempt(|| {
                IntentProjection::decode(bytes.as_slice())
            })
            .map_err(Error::Decode)?;
            #[cfg(not(all(test, sumeragi_core_mutation = "HC218")))]
            if self.count != Some(projection.record_count()) {
                return Err(
                    Error::Source("relay frame omits original certified AMX writes").into(),
                );
            }
            self.offset =
                norito::core::classify_decode_attempt(|| projection.first_offset(bytes.as_slice()))
                    .map_err(Error::Decode)?;
            self.projection = Some(projection);
            self.recheck()?;
            return Ok(Poll::Pending);
        }
        if self.row.is_none() {
            let row = norito::core::classify_decode_attempt(|| {
                self.projection.as_ref().expect("original projection").row(
                    bytes.as_slice(),
                    self.index,
                    self.offset,
                )
            })
            .map_err(Error::Decode)?;
            let Some((row, next)) = row else {
                self.recheck()?;
                self.complete = true;
                return Ok(Poll::Complete);
            };
            if self.previous.is_some_and(|previous| previous >= row.key) {
                return Err(Error::Source("AMX rows are not distinct canonical writes").into());
            }
            self.selected = Some(amx_record_proof(
                self.view,
                self.height,
                row.kind().map_err(Error::Encoding)?,
                row.tx,
            ));
            self.row = Some((row, next));
        }
        let row = self.row.as_ref().expect("selected original row").0;
        let kind = row.kind().map_err(Error::Encoding)?;
        if kind == AmxRecordKind::Prepared {
            return Err(Error::Source("Prepared row on Global root").into());
        }
        if !self.selected_verified {
            if self.probe.is_none() {
                match self
                    .selected
                    .as_mut()
                    .expect("original row verifier")
                    .poll()
                    .map_err(Error::Proof)?
                {
                    NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                    NativeAmxRecordProofPollV1::Complete(proof) => {
                        self.probe = Some(
                            proof
                                .ok_or(Error::Source("AMX row names an absent original record"))?,
                        );
                    }
                }
            }
            let selected = self.selected.as_ref().expect("original row verifier");
            let proof = self
                .probe
                .as_ref()
                .expect("original retained selector proof");
            let record = &proof.canonical().record;
            let projection = self.projection.as_ref().expect("original projection");
            if !selected.matches_completed_execution(self.carrier, projection.ordinary_writes_root)
                || record.witness_key() != row.key
                || record_hash(record)? != row.value
            {
                return Err(
                    Error::Source("AMX row differs from original certified execution").into(),
                );
            }
            self.recheck()?;
            self.selected_verified = true;
            // A Begin already owns the exact authenticated participant selector. Other
            // row selectors retire before acquiring their original Begin selector.
            if kind != AmxRecordKind::Begin {
                self.probe = None;
            }
        }
        if kind == AmxRecordKind::Decision && self.participants_len == 0 && self.begin.is_none() {
            self.begin = Some(amx_record_proof(
                self.view,
                row.begin_height.expect("validated Decision locator"),
                AmxRecordKind::Begin,
                row.tx,
            ));
        }
        if self.participants_len == 0 {
            if self.probe.is_none() {
                match self
                    .begin
                    .as_mut()
                    .expect("original Begin verifier")
                    .poll()
                    .map_err(Error::Proof)?
                {
                    NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                    NativeAmxRecordProofPollV1::Complete(proof) => {
                        self.probe = Some(proof.ok_or(Error::Source(
                            "Decision locator names an absent original Begin",
                        ))?);
                    }
                }
            }
            let proof = self
                .probe
                .as_ref()
                .expect("original retained Begin selector");
            let AmxRecordV1::Begin(record) = &proof.canonical().record else {
                return Err(
                    Error::Source("Decision locator selected a different record kind").into(),
                );
            };
            if record.tx != row.tx
                || record.participants.is_empty()
                || record.participants.len() > MAX_AMX_PARTICIPANTS
            {
                return Err(Error::Source("original Begin participant set differs").into());
            }
            self.recheck()?;
            self.participants_len = record.participants.len();
            self.participants[..self.participants_len].copy_from_slice(&record.participants);
            // Only fixed scalar selectors survive. decision_amx_relay independently verifies
            // exact Begin, Decision and immutable registered target before moving any graph.
            self.probe = None;
            self.begin = None;
            self.selected = None;
            return Ok(Poll::Pending);
        }
        if self.instruction.is_none() {
            match kind {
                AmxRecordKind::Begin => {
                    if self.prepare.is_none() {
                        self.prepare = Some(begin_amx_relay(
                            self.view,
                            self.height,
                            row.tx,
                            self.participants[self.participant_index],
                        )?);
                    }
                    match self
                        .prepare
                        .as_mut()
                        .expect("original Begin delivery")
                        .poll()?
                    {
                        NativeAmxBeginRelayPollV1::Pending => return Ok(Poll::Pending),
                        NativeAmxBeginRelayPollV1::Complete(intent) => {
                            self.instruction = Some(intent)
                        }
                    }
                }
                AmxRecordKind::Decision => {
                    if self.decision.is_none() {
                        self.decision = Some(decision_amx_relay(
                            self.view,
                            row.begin_height.expect("validated Decision locator"),
                            self.height,
                            row.tx,
                            self.participants[self.participant_index],
                        )?);
                    }
                    match self
                        .decision
                        .as_mut()
                        .expect("original Decision delivery")
                        .poll()?
                    {
                        NativeAmxDecisionRelayPollV1::Pending => return Ok(Poll::Pending),
                        NativeAmxDecisionRelayPollV1::Complete(intent) => {
                            self.instruction = Some(intent)
                        }
                    }
                }
                AmxRecordKind::Prepared => {
                    return Err(Error::Source("Prepared row on Global root").into());
                }
            }
        }
        // Retain the exact admitted graph on final source/namespace refusal.
        self.recheck()?;
        let intent = self.instruction.take().expect("original admitted delivery");
        self.decision = None;
        self.prepare = None;
        self.participant_index += 1;
        if self.participant_index == self.participants_len {
            self.finish_row();
        }
        Ok(Poll::Relay(intent))
    }
    /// Complete one original delivery while preserving every pending source after refusal.
    ///
    /// # Errors
    /// The same precise refusal as [`Self::poll`].
    pub fn complete_next(
        &mut self,
    ) -> Result<Option<NativeAmxRelayIntentV1>, NativeAmxRelayDiscoveryErrorV1> {
        loop {
            match self.poll()? {
                NativeAmxRelayDiscoveryPollV1::Pending => {}
                NativeAmxRelayDiscoveryPollV1::Relay(intent) => return Ok(Some(intent)),
                NativeAmxRelayDiscoveryPollV1::Complete => return Ok(None),
            }
        }
    }
}
