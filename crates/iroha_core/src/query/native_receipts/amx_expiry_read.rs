//! Bounded authenticated recovery of an original Global AMX expiry obligation.
//!
//! Discovery cursors are not outcomes. Only an original certified Decision joined to the
//! opaque source intent may suppress a new expiry carrier; it cannot settle participant
//! escrow or declare another, possibly unknown, signed carrier successfully executed.

use super::{
    NativeAmxRecordProofErrorV1, NativeAmxRecordProofIssuedV1, NativeAmxRecordProofOwnedV1,
    NativeAmxRecordProofPollV1, NativeAmxRecordProofReadV1, NativeAmxRelayDescriptorV1,
    NativeAmxRelayIntentV1, NativeAmxRelaySourceV1, amx_record_proof,
};
use crate::state::StateReadOnly;
use iroha_allocation::{ChargedBuffer, ChargedBufferError};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{BlockHeader, consensus::SumeragiRootScope},
    isi::sumeragi_amx::ExpireAmxV1,
    sumeragi_amx::{
        AllocatedAmxRecordProofV1, AmxOutcomeV1, AmxRecordKind, AmxRecordV1, amx_record_witness_key,
    },
};

/// Exact source or physical refusal; never interpreted as absence or an AMX decision.
#[derive(Debug, thiserror::Error)]
pub enum NativeAmxExpiryDecisionErrorV1 {
    /// The original execution pool could not admit retained reader backing.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// Original canonical certification, namespace or proof acquisition refused.
    #[error(transparent)]
    Proof(#[from] NativeAmxRecordProofErrorV1),
    /// Original expiry identity, history or certified Decision does not match.
    #[error("native AMX expiry recovery source: {0}")]
    Source(&'static str),
}

struct OriginalDecision {
    read: Option<NativeAmxRecordProofOwnedV1>,
    proof: Option<AllocatedAmxRecordProofV1>,
    complete: bool,
    height: u64,
}

/// One route's in-memory bounded continuation, never serialized authority.
///
/// The source identity covers the complete opaque descriptor. Already-issued archive work
/// stays in the original paid owner across passes. Restart begins at the original Begin;
/// an old positive locator always triggers a fresh authenticated read.
#[derive(Default)]
pub struct NativeAmxExpiryDecisionCursorV1 {
    binding: Option<NativeAmxRelayDescriptorV1>,
    next: u64,
    positive: Option<u64>,
    original: Option<ChargedBuffer<OriginalDecision>>,
}
impl std::fmt::Debug for NativeAmxExpiryDecisionCursorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeAmxExpiryDecisionCursorV1")
            .field("binding", &self.binding)
            .field("next", &self.next)
            .field("positive", &self.positive)
            .field("has_pending_source", &self.has_pending_source())
            .finish()
    }
}
impl NativeAmxExpiryDecisionCursorV1 {
    /// Whether this continuation belongs to exactly this reconstructed opaque source.
    #[must_use]
    pub fn matches_intent(&self, intent: &NativeAmxRelayIntentV1) -> bool {
        self.binding.as_ref() == Some(intent.descriptor())
    }
    /// Whether the original paid archive job remains unfinished across passes.
    #[must_use]
    pub fn has_pending_source(&self) -> bool {
        self.original
            .as_ref()
            .is_some_and(|original| original.as_slice()[0].read.is_some())
    }
    /// Last positive locator. This value alone proves no outcome and must be reverified.
    #[must_use]
    pub const fn positive_height(&self) -> Option<u64> {
        self.positive
    }
}

/// A Decision from exact native Global history joined to the original expiry intent.
///
/// No public constructor or decoder exists. This authorizes suppressing redundant expiry
/// work only; Commit still requires independently authenticated participant settlement.
#[derive(Debug)]
pub struct VerifiedNativeAmxExpiryDecisionV1 {
    source: NativeAmxRelayDescriptorV1,
    transaction: [u8; 32],
    outcome: AmxOutcomeV1,
    height: u64,
    carrier: HashOf<BlockHeader>,
    timestamp_ms: u64,
}
impl VerifiedNativeAmxExpiryDecisionV1 {
    /// Exact independently reconstructed source intent.
    #[must_use]
    pub const fn source(&self) -> &NativeAmxRelayDescriptorV1 {
        &self.source
    }
    /// Exact canonical AMX transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> [u8; 32] {
        self.transaction
    }
    /// Authenticated Global outcome, not participant monetary effects.
    #[must_use]
    pub const fn outcome(&self) -> AmxOutcomeV1 {
        self.outcome
    }
    /// Original certified Decision height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Exact certified Decision carrier in the selected Global history.
    #[must_use]
    pub const fn carrier(&self) -> HashOf<BlockHeader> {
        self.carrier
    }
    /// Certified ledger timestamp, never local wall time.
    #[must_use]
    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
}

/// Bounded progress, authenticated positive, or exhaustion of this captured finite range.
#[derive(Debug)]
pub enum NativeAmxExpiryDecisionPollV1 {
    /// Original certification/archive work or the next bounded height remains pending.
    Pending,
    /// `None` means this captured range has no Decision; it is never terminal absence.
    Complete(Option<VerifiedNativeAmxExpiryDecisionV1>),
}

/// One captured-view scan. Retain this borrower on a pre-issuance source refusal.
///
/// After issuance, the cursor independently retains its same paid native archive owner and
/// this wrapper may be retired between passes. It never owns a second discovery journal.
#[must_use = "retain pre-issuance source work through refusal or explicitly retire it"]
pub struct NativeAmxExpiryDecisionReadV1<'v, V: StateReadOnly> {
    view: &'v V,
    cursor: &'v mut NativeAmxExpiryDecisionCursorV1,
    borrowed: Option<ChargedBuffer<NativeAmxRecordProofReadV1<'v, V>>>,
    descriptor: NativeAmxRelayDescriptorV1,
    transaction: [u8; 32],
    deadline: u64,
    expires_at_ms: u64,
    end: u64,
    complete: bool,
}

/// Scan the original Begin through `min(deadline + 1, captured_tip)` for its Decision.
///
/// `poll` advances at most one original native proof stage or one authenticated absent
/// height. A cached positive is selected again, never trusted. The caller can bound polls
/// per pass, keep the same cursor and continue ordinary independent-route work.
///
/// # Errors
/// A non-expiry intent, substituted root/history, malformed bound or original-pool refusal.
pub fn expiry_amx_decision<'v, V: StateReadOnly>(
    view: &'v V,
    intent: &NativeAmxRelayIntentV1,
    cursor: &'v mut NativeAmxExpiryDecisionCursorV1,
) -> Result<NativeAmxExpiryDecisionReadV1<'v, V>, NativeAmxExpiryDecisionErrorV1> {
    use NativeAmxExpiryDecisionErrorV1 as Error;
    let descriptor = *intent.descriptor();
    let expiry = intent
        .instruction()
        .as_any()
        .downcast_ref::<ExpireAmxV1>()
        .ok_or(Error::Source(
            "recovery requires the opaque original expiry instruction",
        ))?;
    let begin = intent
        .instruction()
        .amx_expiry_begin()
        .and_then(|proof| match &proof.record {
            AmxRecordV1::Begin(begin) => Some(begin),
            _ => None,
        })
        .ok_or(Error::Source("expiry lost its original funded Begin graph"))?;
    if descriptor.source_scope() != SumeragiRootScope::Global
        || descriptor.target_scope() != SumeragiRootScope::Global
        || descriptor.source_network() != descriptor.target_network()
        || descriptor.source_height() < 2
        || descriptor.ready_at_ms() != Some(begin.expires_at_ms)
        || descriptor.source()
            != (NativeAmxRelaySourceV1::Record {
                key: amx_record_witness_key(AmxRecordKind::Begin, begin.tx),
            })
        || expiry.tx != begin.tx
    {
        return Err(Error::Source("expiry and captured Global root differ"));
    }
    let begin_index = usize::try_from(descriptor.source_height() - 1)
        .map_err(|_| Error::Source("Begin height cannot index captured history"))?;
    if !cfg!(all(test, sumeragi_core_mutation = "HC338"))
        && (descriptor.source_network() != *view.network_id()
            || view.native_execution_tip().map(|tip| tip.root_scope())
                != Some(SumeragiRootScope::Global)
            || view.block_hashes().get(begin_index).copied() != Some(descriptor.source_carrier()))
    {
        return Err(Error::Source(
            "expiry Begin carrier differs from captured history",
        ));
    }
    let end = begin
        .deadline
        .checked_add(1)
        .ok_or(Error::Source(
            "expiry deadline overflows its finite decision interval",
        ))?
        .min(u64::try_from(view.height()).map_err(|_| Error::Source("source height overflows"))?);
    if end < descriptor.source_height() {
        return Err(Error::Source(
            "captured history precedes the original Begin",
        ));
    }
    if !cursor.matches_intent(intent) {
        *cursor = NativeAmxExpiryDecisionCursorV1 {
            binding: Some(descriptor),
            next: descriptor.source_height(),
            positive: None,
            original: None,
        };
    }
    if cursor.positive.is_some_and(|height| height > end) {
        return Err(Error::Source(
            "captured history rolled back an authenticated positive locator",
        ));
    }
    if cursor.next.saturating_sub(1) > end {
        return Err(Error::Source(
            "captured history rolled back an authenticated scan prefix",
        ));
    }
    Ok(NativeAmxExpiryDecisionReadV1 {
        view,
        cursor,
        borrowed: None,
        descriptor,
        transaction: begin.tx,
        deadline: begin.deadline,
        expires_at_ms: begin.expires_at_ms,
        end,
        complete: false,
    })
}

impl<V: StateReadOnly> NativeAmxExpiryDecisionReadV1<'_, V> {
    /// Whether retiring this wrapper preserves every admitted unfinished source in its cursor.
    /// A false result requires keeping this borrower and captured view through refusal.
    #[must_use]
    pub fn can_retire(&self) -> bool {
        self.borrowed.is_none()
    }

    /// Advance one original stage, preserving admitted archive work through local refusal.
    ///
    /// # Errors
    /// Exact native source/resource refusal; a completed wrapper cannot be polled again.
    pub fn poll(
        &mut self,
    ) -> Result<NativeAmxExpiryDecisionPollV1, NativeAmxExpiryDecisionErrorV1> {
        use NativeAmxExpiryDecisionErrorV1 as Error;
        use NativeAmxExpiryDecisionPollV1 as Poll;
        if self.complete {
            return Err(Error::Source("expiry recovery read already completed"));
        }
        #[cfg(all(test, sumeragi_core_mutation = "HC339"))]
        if let Some(height) = self.cursor.positive {
            // Mutation: promote a discovery locator into outcome authority without acquiring
            // its original certified source. Production never constructs a result this way.
            let index = usize::try_from(height - 1)
                .map_err(|_| Error::Source("cached height cannot index captured history"))?;
            let carrier = self
                .view
                .block_hashes()
                .get(index)
                .copied()
                .ok_or(Error::Source("cached carrier absent from captured history"))?;
            self.complete = true;
            return Ok(Poll::Complete(Some(VerifiedNativeAmxExpiryDecisionV1 {
                source: self.descriptor,
                transaction: self.transaction,
                outcome: AmxOutcomeV1::Abort,
                height,
                carrier,
                timestamp_ms: self.expires_at_ms,
            })));
        }
        let height = self.cursor.positive.unwrap_or(self.cursor.next);
        if height > self.end {
            self.complete = true;
            return Ok(Poll::Complete(None));
        }
        let cache = self.view.prepared_contract_cache();
        let budget = cache.execution_budget();
        if self
            .cursor
            .original
            .as_ref()
            .is_some_and(|original| !original.belongs_to(budget))
        {
            return Err(Error::Source(
                "expiry cursor retains another original execution pool",
            ));
        }
        if self.cursor.original.is_none() {
            let mut original = ChargedBuffer::new(1, budget)?;
            original.push_reserved(OriginalDecision {
                read: None,
                proof: None,
                complete: false,
                height,
            });
            self.cursor.original = Some(original);
        }
        let slot = &mut self
            .cursor
            .original
            .as_mut()
            .expect("admitted original slot")
            .as_mut_slice()[0];
        if slot.height != height {
            return Err(Error::Source("retained Decision source height differs"));
        }
        if slot.read.is_none() {
            if self.borrowed.is_none() {
                let mut borrowed = ChargedBuffer::new(1, budget)?;
                borrowed.push_reserved(amx_record_proof(
                    self.view,
                    height,
                    AmxRecordKind::Decision,
                    self.transaction,
                ));
                self.borrowed = Some(borrowed);
            }
            let issued = self
                .borrowed
                .as_mut()
                .expect("original borrowed source")
                .as_mut_slice()[0]
                .try_issue()?;
            match issued {
                NativeAmxRecordProofIssuedV1::Acquired(read) => slot.read = Some(read),
                NativeAmxRecordProofIssuedV1::Refused { original, cause } => {
                    slot.read = Some(original);
                    self.borrowed = None;
                    return Err(cause.into());
                }
            }
            self.borrowed = None;
        }
        let read = slot.read.as_mut().expect("issued original source");
        if !slot.complete {
            match read.poll()? {
                NativeAmxRecordProofPollV1::Pending => return Ok(Poll::Pending),
                NativeAmxRecordProofPollV1::Complete(proof) => {
                    slot.proof = proof;
                    slot.complete = true;
                }
            }
        }
        let source = read.completed_original()?;
        let header = source
            .header()
            .ok_or(Error::Source("Decision lacks original certified header"))?;
        let index = usize::try_from(height - 1)
            .map_err(|_| Error::Source("Decision height cannot index history"))?;
        if source.root_scope() != SumeragiRootScope::Global
            || header.instance.0 != self.descriptor.target_instance()
            || source.commitment().schedule.current.network_id != self.descriptor.source_network()
            || self.view.block_hashes().get(index).copied() != Some(source.block_hash())
        {
            return Err(Error::Source(
                "Decision source differs from original Global intent",
            ));
        }
        let Some(proof) = &slot.proof else {
            if self.cursor.positive.is_some() {
                return Err(Error::Source("authenticated positive Decision disappeared"));
            }
            self.cursor.next = height
                .checked_add(1)
                .ok_or(Error::Source("Decision scan height overflow"))?;
            self.cursor.original = None;
            if self.cursor.next > self.end {
                self.complete = true;
                return Ok(Poll::Complete(None));
            }
            return Ok(Poll::Pending);
        };
        let AmxRecordV1::Decision(decision) = &proof.canonical().record else {
            return Err(Error::Source("selected record is not a Decision"));
        };
        let timestamp_ms = source.certified_result().header().timestamp_ms();
        if decision.tx != self.transaction
            || (decision.outcome == AmxOutcomeV1::Commit
                && (height > self.deadline || timestamp_ms >= self.expires_at_ms))
        {
            return Err(Error::Source(
                "Decision differs from exact intent or its signed boundary",
            ));
        }
        let verified = VerifiedNativeAmxExpiryDecisionV1 {
            source: self.descriptor,
            transaction: self.transaction,
            outcome: decision.outcome,
            height,
            carrier: source.block_hash(),
            timestamp_ms,
        };
        self.cursor.positive = Some(height);
        self.cursor.original = None;
        self.complete = true;
        Ok(Poll::Complete(Some(verified)))
    }
}
