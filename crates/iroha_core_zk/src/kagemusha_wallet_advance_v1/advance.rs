//! `Advance` (spec §§3.1, 4.1, 4.2 steps 2-4, 5.3; G2 design rev 2 §4 A0-A12).
//!
//! `Advance(expected_head, new_head, proof_digest, operation_id, capsule)` either leaves the
//! old head usable without releasing a receipt, or durably selects the exact new head and
//! retains everything needed to finish and return its output:
//!
//! - **A0** reconcile the slot (which also finishes an interrupted selected head offline);
//! - **A1** return the retained result of an operation identity that already has a selected
//!   head, a record or a tombstone, and refuse its reuse with changed inputs;
//! - **A2** validate the request against the current marker; **A3** reserve capacity;
//! - **A4** stage both capsule copies; **A5** publish the Selected marker (the commit point);
//! - **A6** retire the older marker; **A7** sign the receipt body under the Selected-marker
//!   capability, unless a valid record for the head already exists; **A8** persist the
//!   completion record in two copies; **A9** publish the Released marker binding its digest;
//!   **A10** raise the iOS anchor; **A11** retire the Selected marker; **A12** regrow the
//!   ballast and return the exact retained frame.
//!
//! A write whose outcome is unknown from A4 on returns `Pending` and poisons the slot; the next
//! reconcile resolves it to the released result or to not-performed. Once the Selected marker
//! is durable (A5) the operation is performed and its debit irreversible, so every later
//! failure except custody loss is `Pending` (its reason is kept as a diagnostic,
//! [`KagemushaWalletProviderV1::pending_reason`]), never an error that could be shown as a
//! rejected operation. Everything the transition owner can refuse before signing (the receipt
//! body) is asked in A2, before anything is staged. Signing never happens under a Released,
//! Enrollment or Terminal marker, so a released head yields one result only.
//!
//! While a selected head waits for its receipt, a retry of an older operation still returns
//! its retained result, archive tombstone or delivery-data loss (A1); only an operation the
//! slot knows nothing about is `StaleHead`.
//!
//! The provider is generic over the capsule ([`KagemushaWalletAdvanceCapsuleV1`]) and over the
//! receipt body and released output, which the state owner supplies
//! ([`KagemushaWalletTransitionOwnerV1`]): a design that adds proofs or retained objects to
//! the capsule, or a later background proof, changes those owners, not this sequence.

use iroha_data_model::kagemusha::{
    KagemushaDeviceSignatureV1, KagemushaWalletEffectV1, KagemushaWalletMarkerStateV1,
    KagemushaWalletMarkerV1, KagemushaWalletOperationKindV1, KagemushaWalletRecoveryCapsuleV1,
    KagemushaWalletStateCommitmentV1,
};
use rand::rand_core::TryRngCore as _;

use super::{
    KagemushaWalletLostCustodyV1, KagemushaWalletProviderErrorV1,
    anchor::kagemusha_wallet_raise_anchor_v1,
    capsule::{
        KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1, KagemushaWalletFrozenFrameV1,
        kagemusha_wallet_discard_staged_capsule_v1, kagemusha_wallet_stage_capsule_v1,
    },
    completion::{
        KagemushaWalletCompletionExpectationV1, KagemushaWalletCompletionFrameV1,
        kagemusha_wallet_load_completion_v1, kagemusha_wallet_stage_completion_v1,
    },
    layout::{
        KAGEMUSHA_WALLET_BALLAST_NAME_V1, KagemushaWalletCustodyDirV1, KagemushaWalletSlotIdV1,
        kagemusha_wallet_fixed_name_v1, kagemusha_wallet_list_dir_v1,
        kagemusha_wallet_require_removed_v1,
    },
    marker::{
        KagemushaWalletDurableMarkerV1, KagemushaWalletMarkerPhaseV1,
        KagemushaWalletMarkerPublicationV1, KagemushaWalletMarkerRecordV1,
        kagemusha_wallet_load_current_marker_v1, kagemusha_wallet_publish_marker_v1,
        kagemusha_wallet_retire_markers_v1,
    },
    platform::{
        KagemushaWalletEntryKindV1, KagemushaWalletFsV1, KagemushaWalletPlatformV1,
        KagemushaWalletPublishOutcomeV1, KagemushaWalletSignErrorV1, KagemushaWalletUnavailableV1,
        kagemusha_wallet_boot_stamp_v1, kagemusha_wallet_sign_receipt_body_v1,
    },
    provider::{KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1},
    retained::{
        KagemushaWalletLookupV1, KagemushaWalletRetainedStatusV1, KagemushaWalletRetainedV1,
        KagemushaWalletTombstoneV1, OlderCompletionV1, load_older_completion, read_tombstone,
    },
};

/// Free space kept beyond both capsule copies and the state owner's growth (design A3).
pub const KAGEMUSHA_WALLET_CAPACITY_HEADROOM_BYTES_V1: u64 = 64 * 1024;

// ---------------------------------------------------------------------------------------
// Capsule and transition-owner interfaces
// ---------------------------------------------------------------------------------------

/// How an operation may use storage before its head is selected (spec §5.3; design A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletCapacityClassV1 {
    /// Grows local state; needs free space beyond an intact ballast.
    Growth,
    /// Outbox cleanup (`ArchiveSent`); may draw on the ballast so it is never stranded by a
    /// full disk.
    Cleanup,
}

/// Frozen recovery capsule as `Advance` sees it: the head it selects and the bindings checked
/// against the request and the current marker. The provider never interprets anything else
/// the capsule retains.
pub trait KagemushaWalletAdvanceCapsuleV1: KagemushaWalletFrozenFrameV1 {
    /// Decode binding of the capsules covered by `marker` (G1: its scheme).
    fn marker_binding(marker: &KagemushaWalletMarkerV1) -> Self::Binding;
    /// Operation identity, recomputed by the owner from the capsule's statement.
    fn operation_id(&self) -> [u8; 32];
    /// Head marker state selecting this capsule's successor (G1 `Head`).
    ///
    /// # Errors
    ///
    /// Rejects a capsule that is invalid or cannot be digested.
    fn head_marker_state(
        &self,
    ) -> Result<KagemushaWalletMarkerStateV1, KagemushaWalletProviderErrorV1>;
    /// Predecessor state commitment; zero for Bootstrap.
    fn predecessor_commitment(&self) -> KagemushaWalletStateCommitmentV1;
    /// Operation-dependent `proof_digest` the receipt binds (spec §4.1; G1
    /// `kagemusha_wallet_proof_digest_v1`), one canonical σ-field value:
    /// `P_bytes(kgwprf_1, LE32 len(Ω) || Ω || LE32 len(σ) || σ)` over Ω(pred) and the step proof
    /// for Send, Unload and Retiring, and the distinct σ-only domain
    /// `P_bytes(kgwstep1, LE32 len(σ) || σ)` for every other operation.
    ///
    /// # Errors
    ///
    /// Rejects a capsule whose proof material cannot be digested.
    fn bound_proof_digest(&self) -> Result<[u8; 32], KagemushaWalletProviderErrorV1>;
    /// Generation-0 marker digest bound by a Bootstrap capsule; `None` for every other kind.
    fn bootstrap_enrollment_marker(&self) -> Option<[u8; 32]>;
    /// Capacity class of the operation.
    fn capacity_class(&self) -> KagemushaWalletCapacityClassV1;
    /// Require that the head marker `selected` (the Selected successor this capsule would
    /// install) covers exactly this capsule: its scheme, wallet and head (G1:
    /// `KagemushaWalletMarkerV1::require_capsule`). Checked in A2, so a capsule bound to another
    /// wallet or scheme is refused before anything is staged.
    ///
    /// # Errors
    ///
    /// Rejects a capsule the marker does not cover.
    fn require_marker(
        &self,
        selected: &KagemushaWalletMarkerV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1>;
}

impl KagemushaWalletAdvanceCapsuleV1 for KagemushaWalletRecoveryCapsuleV1 {
    fn marker_binding(marker: &KagemushaWalletMarkerV1) -> [u8; 32] {
        marker.scheme_id
    }

    fn require_marker(
        &self,
        selected: &KagemushaWalletMarkerV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        selected
            .require_capsule(self)
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                field: "capsule.marker",
            })
    }

    fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }

    fn head_marker_state(
        &self,
    ) -> Result<KagemushaWalletMarkerStateV1, KagemushaWalletProviderErrorV1> {
        Self::head_marker_state(self)
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: "capsule" })
    }

    fn predecessor_commitment(&self) -> KagemushaWalletStateCommitmentV1 {
        self.statement.predecessor
    }

    fn bound_proof_digest(&self) -> Result<[u8; 32], KagemushaWalletProviderErrorV1> {
        self.proof_digest()
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                field: "capsule.proof_digest",
            })
    }

    fn bootstrap_enrollment_marker(&self) -> Option<[u8; 32]> {
        match self.statement.effect {
            KagemushaWalletEffectV1::Bootstrap {
                enrollment_marker, ..
            } => Some(enrollment_marker),
            _ => None,
        }
    }

    fn capacity_class(&self) -> KagemushaWalletCapacityClassV1 {
        if self.kind == KagemushaWalletOperationKindV1::ArchiveSent {
            KagemushaWalletCapacityClassV1::Cleanup
        } else {
            KagemushaWalletCapacityClassV1::Growth
        }
    }
}

/// The state owner's side of `Advance`: the exact receipt body the payment key signs and the
/// pure assembly of the released output from the frozen capsule and its receipt signature.
/// Both are used by the fresh path and by offline recovery of a selected head.
///
/// `receipt_body` is asked in A2, before anything is staged, so a capsule the owner cannot
/// certify is never selected. Both must be deterministic functions of the frozen capsule
/// (and its signature): recovery asks again after a restart. A failure after selection leaves
/// the operation performed and pending.
// The native state owner's TransitionOwner derives the receipt body from the credential,
// operation proof digest and retained Payment digest, then assembles the exact Payment or
// Package. Its Coordinator authenticates source maps and re-derives the frozen successor
// before calling Advance; this provider interface owns the durable signing boundary.
pub trait KagemushaWalletTransitionOwnerV1<C, R> {
    /// Exact `receipt-body` transcript for `capsule` whose frame digest is `capsule_digest`.
    ///
    /// # Errors
    ///
    /// Rejects a capsule the owner cannot certify; nothing is signed.
    fn receipt_body(
        &self,
        capsule: &C,
        capsule_digest: &[u8; 32],
    ) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1>;

    /// Completion record holding the receipt and the exact released output.
    ///
    /// # Errors
    ///
    /// Rejects an output the owner cannot assemble; nothing is written.
    fn assemble(
        &self,
        capsule: &C,
        capsule_digest: &[u8; 32],
        signature: &KagemushaDeviceSignatureV1,
    ) -> Result<R, KagemushaWalletProviderErrorV1>;
}

// ---------------------------------------------------------------------------------------
// Request and outcome
// ---------------------------------------------------------------------------------------

/// Head the caller expects to be current.
// A short-lived request value; the released head's fields stay inline.
#[allow(variant_size_differences)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KagemushaWalletExpectedHeadV1 {
    /// Bootstrap from the generation-0 enrollment marker with this G1 marker digest.
    Enrollment {
        /// G1 marker digest of the enrollment marker.
        marker_digest: [u8; 32],
    },
    /// The released head with these fields.
    Released {
        /// Head sequence.
        sequence: u128,
        /// Head state commitment.
        head: KagemushaWalletStateCommitmentV1,
        /// Capsule digest of the head.
        capsule_digest: [u8; 32],
    },
}

impl KagemushaWalletExpectedHeadV1 {
    /// Expectation naming `record` (an Enrollment or Released marker).
    #[must_use]
    pub fn of(record: &KagemushaWalletMarkerRecordV1) -> Option<Self> {
        match (record.phase(), record.marker().state) {
            (KagemushaWalletMarkerPhaseV1::Enrollment, _) => Some(Self::Enrollment {
                marker_digest: *record.marker_digest(),
            }),
            (
                KagemushaWalletMarkerPhaseV1::Released,
                KagemushaWalletMarkerStateV1::Head {
                    sequence,
                    head,
                    capsule_digest,
                    ..
                },
            ) => Some(Self::Released {
                sequence,
                head,
                capsule_digest,
            }),
            _ => None,
        }
    }
}

/// One `Advance` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletAdvanceRequestV1<C> {
    /// Head the caller built the transition on.
    pub expected: KagemushaWalletExpectedHeadV1,
    /// Operation identity.
    pub operation_id: [u8; 32],
    /// New head commitment.
    pub new_head: KagemushaWalletStateCommitmentV1,
    /// Operation-dependent `proof_digest` the receipt binds (spec §4.1), one canonical σ-field
    /// value: over Ω(pred) and σ for Send, Unload and Retiring, over σ alone otherwise.
    pub proof_digest: [u8; 32],
    /// Frozen recovery capsule.
    pub capsule: C,
    /// Additional bytes the state owner's maps and archive grow by.
    pub growth_bytes: u64,
}

/// Why an `Advance` was not performed; the old head stays current and nothing was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletNotPerformedV1 {
    /// The expected head is no longer current (another operation won it).
    StaleHead,
    /// Storage is short; retry after space is freed. Nothing was selected; capsule copies
    /// staged before the disk filled are discarded at once, or at the latest by the next
    /// reconcile.
    CapacityWait,
    /// The request is inconsistent with itself or the current head.
    Invalid {
        /// Stable field label.
        field: &'static str,
    },
}

/// Outcome of one `Advance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KagemushaWalletAdvanceOutcomeV1<R> {
    /// Released: the exact retained result, identical on every retry.
    Released {
        /// The retained result.
        retained: Box<KagemushaWalletRetainedV1<R>>,
        /// Whether an earlier call had already released or selected it.
        resumed: bool,
    },
    /// Not performed; the old head stays current.
    NotPerformed(KagemushaWalletNotPerformedV1),
    /// Outcome unknown or signing unavailable; reconcile (or retry) resolves it.
    Pending {
        /// Operation identity.
        operation_id: [u8; 32],
    },
    /// The operation's record was pruned after its tombstone.
    Archived(Box<KagemushaWalletTombstoneV1>),
    /// The operation was released but every copy of its record is lost.
    DeliveryDataLoss {
        /// Operation identity.
        operation_id: [u8; 32],
    },
}

/// Result of finishing a durable Selected marker (A6-A12).
pub(super) enum FinishedV1<R> {
    /// Released: the retained result and the durable Released marker.
    Released(KagemushaWalletRetainedV1<R>, KagemushaWalletDurableMarkerV1),
    /// Not released, and nothing was written after the retirement of lower generations: the
    /// key could not sign, or the transition owner refused. The head stays selected.
    Stalled(KagemushaWalletProviderErrorV1),
}

fn invalid(field: &'static str) -> KagemushaWalletNotPerformedV1 {
    KagemushaWalletNotPerformedV1::Invalid { field }
}

/// Head commitment of a head marker.
fn head_commitment(
    record: &KagemushaWalletMarkerRecordV1,
) -> Option<KagemushaWalletStateCommitmentV1> {
    match record.marker().state {
        KagemushaWalletMarkerStateV1::Head { head, .. } => Some(head),
        _ => None,
    }
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Run `Advance` on `slot` (design A0-A12).
    ///
    /// # Errors
    ///
    /// `Terminal` for a terminal slot, `Invalid` for a slot without an enrollment marker,
    /// `OperationIdConflict` when the operation identity is retained with other inputs, and the
    /// reconcile errors. Unknown write outcomes from A4 on, and every failure after the
    /// Selected marker is durable except custody loss (`LostCustody`, `KeyLost`), are
    /// `Ok(Pending)`, never errors.
    pub fn advance(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
        request: &KagemushaWalletAdvanceRequestV1<C>,
    ) -> Result<KagemushaWalletAdvanceOutcomeV1<R>, KagemushaWalletProviderErrorV1> {
        let operation_id = request.operation_id;
        // A0.
        let current = match self.reconcile_slot(slot, Some(owner))? {
            KagemushaWalletSlotStatusV1::Enrollment(record)
            | KagemushaWalletSlotStatusV1::Released(record) => record,
            KagemushaWalletSlotStatusV1::Pending(record) => {
                return self.advance_while_pending(slot, &record, request);
            }
            KagemushaWalletSlotStatusV1::Terminal(_) => {
                return Err(KagemushaWalletProviderErrorV1::Terminal);
            }
            KagemushaWalletSlotStatusV1::Empty
            | KagemushaWalletSlotStatusV1::IntentOnly
            | KagemushaWalletSlotStatusV1::SlotAbandoned => {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "slot.not_enrolled",
                });
            }
        };
        let Ok(frame) = request.capsule.encode_frame() else {
            return Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(invalid(
                "capsule",
            )));
        };
        let capsule_digest = C::frame_digest(&frame);
        // A1.
        if let Some(outcome) =
            self.retained_outcome(slot, &current, &operation_id, &capsule_digest)?
        {
            return Ok(outcome);
        }
        // "Nothing recorded" counts only while storage stayed available.
        self.require_storage()?;
        // A2.
        let boot = self.boot();
        let (selected, receipt_body) =
            match self.validate_request(&current, request, &frame, &capsule_digest, &boot, owner) {
                Ok(validated) => validated,
                Err(reason) => return Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(reason)),
            };
        let durable = self
            .cache
            .get(slot)
            .map(|cached| cached.durable.clone())
            .filter(|durable| durable.record() == &current)
            .ok_or(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            ))?;
        // A3.
        let class = request.capsule.capacity_class();
        let reserved = self.reserve_capacity(class, frame.len(), request.growth_bytes);
        if !self.guard(slot, reserved)? {
            return Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
                KagemushaWalletNotPerformedV1::CapacityWait,
            ));
        }
        // A4-A12: the slot is unverified until a release re-caches it.
        self.poison(slot);
        self.commit(
            slot,
            owner,
            &durable,
            request,
            selected,
            receipt_body,
            &boot,
        )
    }

    /// Look up the retained result of `operation_id` on `slot` without signing.
    ///
    /// # Errors
    ///
    /// The reconcile and read errors; a released record lost in every copy is
    /// `Ok(DeliveryDataLoss)`, never an error. Every answer counts only while protected storage
    /// stayed available (`Unavailable` otherwise), so a locked store never reads as an unknown
    /// or lost operation.
    pub fn lookup(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        operation_id: &[u8; 32],
    ) -> Result<KagemushaWalletLookupV1<R>, KagemushaWalletProviderErrorV1> {
        let answer = self.lookup_answer(slot, operation_id)?;
        self.require_storage()?;
        Ok(answer)
    }

    /// [`Self::lookup`] before the final storage check.
    fn lookup_answer(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        operation_id: &[u8; 32],
    ) -> Result<KagemushaWalletLookupV1<R>, KagemushaWalletProviderErrorV1> {
        let status = match self.reconcile_slot(slot, None) {
            Ok(status) => status,
            Err(KagemushaWalletProviderErrorV1::LostCustody(
                KagemushaWalletLostCustodyV1::CompletionLost,
            )) => {
                // The current head's record is lost: report it, and answer other operations.
                let current =
                    kagemusha_wallet_load_current_marker_v1(&self.store, slot, &self.scheme_id)?
                        .ok_or(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                            object: "marker",
                        })?;
                if current
                    .record()
                    .head()
                    .is_some_and(|(_, head_op, _)| head_op == *operation_id)
                {
                    return Ok(KagemushaWalletLookupV1::DeliveryDataLoss);
                }
                return self.lookup_older(slot, current.record(), operation_id);
            }
            Err(error) => return Err(error),
        };
        let Some(current) = status.marker() else {
            return Ok(KagemushaWalletLookupV1::Unknown);
        };
        match (&status, current.head()) {
            (KagemushaWalletSlotStatusV1::Pending(_), Some((_, head_op, capsule_digest)))
                if head_op == *operation_id =>
            {
                Ok(KagemushaWalletLookupV1::SelectedUnsigned { capsule_digest })
            }
            (KagemushaWalletSlotStatusV1::Released(record), Some((_, head_op, _)))
                if head_op == *operation_id =>
            {
                Ok(match self.load_head_retained(slot, record) {
                    Ok(retained) => KagemushaWalletLookupV1::Retained(Box::new(retained)),
                    Err(KagemushaWalletProviderErrorV1::LostCustody(
                        KagemushaWalletLostCustodyV1::CompletionLost,
                    )) => KagemushaWalletLookupV1::DeliveryDataLoss,
                    Err(error) => return Err(error),
                })
            }
            _ => {
                let current = current.clone();
                self.lookup_older(slot, &current, operation_id)
            }
        }
    }

    /// Advance attempted while a selected head of the slot is still waiting for its receipt.
    ///
    /// The selected operation itself is pending (its changed inputs conflict). Any other
    /// operation gets the A1 answer first: a retained result, an archive tombstone or
    /// delivery-data loss of an older released operation is reported as such (a released,
    /// irreversible Send is never shown as not performed); only an operation without any
    /// record is `StaleHead`.
    fn advance_while_pending(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        current: &KagemushaWalletMarkerRecordV1,
        request: &KagemushaWalletAdvanceRequestV1<C>,
    ) -> Result<KagemushaWalletAdvanceOutcomeV1<R>, KagemushaWalletProviderErrorV1> {
        let Some((_, head_op, head_capsule)) = current.head() else {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.phase",
            });
        };
        let digest = request
            .capsule
            .encode_frame()
            .ok()
            .map(|frame| C::frame_digest(&frame));
        if head_op == request.operation_id {
            if digest != Some(head_capsule) {
                return Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
                    retained: KagemushaWalletRetainedStatusV1::Selected {
                        capsule_digest: head_capsule,
                    },
                });
            }
            return Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
                operation_id: head_op,
            });
        }
        let Some(capsule_digest) = digest else {
            return Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(invalid(
                "capsule",
            )));
        };
        if let Some(outcome) =
            self.older_outcome(slot, current, &request.operation_id, &capsule_digest)?
        {
            return Ok(outcome);
        }
        // "Nothing recorded" counts only while storage stayed available.
        self.require_storage()?;
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::StaleHead,
        ))
    }

    /// A1: the retained answer for an operation identity that already has a head, a record
    /// or a tombstone; `None` when the identity is free.
    fn retained_outcome(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        current: &KagemushaWalletMarkerRecordV1,
        operation_id: &[u8; 32],
        capsule_digest: &[u8; 32],
    ) -> Result<Option<KagemushaWalletAdvanceOutcomeV1<R>>, KagemushaWalletProviderErrorV1> {
        if let Some((_, head_op, head_capsule)) = current.head()
            && head_op == *operation_id
        {
            let retained = self.load_head_retained(slot, current)?;
            if head_capsule != *capsule_digest {
                return Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
                    retained: retained.status(),
                });
            }
            return Ok(Some(KagemushaWalletAdvanceOutcomeV1::Released {
                retained: Box::new(retained),
                resumed: true,
            }));
        }
        self.older_outcome(slot, current, operation_id, capsule_digest)
    }

    /// A1 for an operation other than the current head's: its retained result, tombstone or
    /// delivery-data loss; `None` when nothing is recorded for it.
    fn older_outcome(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        current: &KagemushaWalletMarkerRecordV1,
        operation_id: &[u8; 32],
        capsule_digest: &[u8; 32],
    ) -> Result<Option<KagemushaWalletAdvanceOutcomeV1<R>>, KagemushaWalletProviderErrorV1> {
        let conflict = |retained| KagemushaWalletProviderErrorV1::OperationIdConflict { retained };
        Ok(match self.lookup_older(slot, current, operation_id)? {
            KagemushaWalletLookupV1::Retained(retained) => {
                if retained.capsule_digest != *capsule_digest {
                    return Err(conflict(retained.status()));
                }
                Some(KagemushaWalletAdvanceOutcomeV1::Released {
                    retained,
                    resumed: true,
                })
            }
            KagemushaWalletLookupV1::Archived(tombstone) => {
                if tombstone.capsule_digest != *capsule_digest {
                    return Err(conflict(tombstone.status()));
                }
                Some(KagemushaWalletAdvanceOutcomeV1::Archived(tombstone))
            }
            KagemushaWalletLookupV1::DeliveryDataLoss => {
                Some(KagemushaWalletAdvanceOutcomeV1::DeliveryDataLoss {
                    operation_id: *operation_id,
                })
            }
            KagemushaWalletLookupV1::SelectedUnsigned { .. } | KagemushaWalletLookupV1::Unknown => {
                None
            }
        })
    }

    /// Retained result of the current Released head.
    fn load_head_retained(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        record: &KagemushaWalletMarkerRecordV1,
    ) -> Result<KagemushaWalletRetainedV1<R>, KagemushaWalletProviderErrorV1> {
        let expectation = KagemushaWalletCompletionExpectationV1::for_marker(record).ok_or(
            KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.phase",
            },
        )?;
        let pair = kagemusha_wallet_load_completion_v1::<F, R>(
            &self.store,
            slot,
            &expectation,
            &R::marker_binding(record.marker()),
        )?
        .ok_or(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::CompletionLost,
        ))?;
        Ok(KagemushaWalletRetainedV1::from_pair(pair))
    }

    /// Lookup of an operation other than the current head's.
    fn lookup_older(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        current: &KagemushaWalletMarkerRecordV1,
        operation_id: &[u8; 32],
    ) -> Result<KagemushaWalletLookupV1<R>, KagemushaWalletProviderErrorV1> {
        let binding = R::marker_binding(current.marker());
        Ok(
            match load_older_completion::<F, R>(&self.store, slot, operation_id, &binding)? {
                OlderCompletionV1::Found(pair) => KagemushaWalletLookupV1::Retained(Box::new(
                    KagemushaWalletRetainedV1::from_pair(pair),
                )),
                OlderCompletionV1::Invalid => KagemushaWalletLookupV1::DeliveryDataLoss,
                OlderCompletionV1::Absent => match read_tombstone(&self.store, slot, operation_id)?
                {
                    Some(Some(tombstone)) => KagemushaWalletLookupV1::Archived(Box::new(tombstone)),
                    Some(None) => KagemushaWalletLookupV1::DeliveryDataLoss,
                    None => KagemushaWalletLookupV1::Unknown,
                },
            },
        )
    }

    /// A2: validate `request` against the current Enrollment or Released marker, build the
    /// Selected successor and ask the transition owner for the exact receipt body.
    ///
    /// Everything that could make a selected head unfinishable is refused here, before
    /// anything is staged: a capsule frame that does not decode under the marker's binding,
    /// a capsule the Selected marker does not cover (another wallet or scheme), and a capsule
    /// the owner cannot certify.
    fn validate_request(
        &self,
        current: &KagemushaWalletMarkerRecordV1,
        request: &KagemushaWalletAdvanceRequestV1<C>,
        frame: &[u8],
        capsule_digest: &[u8; 32],
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
    ) -> Result<(KagemushaWalletMarkerRecordV1, Vec<u8>), KagemushaWalletNotPerformedV1> {
        if KagemushaWalletExpectedHeadV1::of(current) != Some(request.expected) {
            return Err(KagemushaWalletNotPerformedV1::StaleHead);
        }
        let capsule = &request.capsule;
        let state = capsule
            .head_marker_state()
            .map_err(|_| invalid("capsule"))?;
        let KagemushaWalletMarkerStateV1::Head {
            operation_id,
            head,
            capsule_digest: state_capsule_digest,
            ..
        } = state
        else {
            return Err(invalid("capsule.head"));
        };
        if state_capsule_digest != *capsule_digest {
            return Err(invalid("capsule.digest"));
        }
        if request.operation_id != operation_id || capsule.operation_id() != operation_id {
            return Err(invalid("operation_id"));
        }
        if request.new_head != head {
            return Err(invalid("new_head"));
        }
        // For Send, Unload and Retiring, the native Coordinator requires the source-selected
        // durable fold of this expected head and exact equality with capsule Ω(pred) before
        // dispatch. Its collection owner retains witnesses until a verified durable Ω covers
        // them. Advance independently binds the capsule to the currently selected head below.
        let bound = capsule
            .bound_proof_digest()
            .map_err(|_| invalid("proof_digest"))?;
        if request.proof_digest != bound {
            return Err(invalid("proof_digest"));
        }
        let linked = match current.phase() {
            KagemushaWalletMarkerPhaseV1::Enrollment => {
                capsule.predecessor_commitment().is_zero()
                    && capsule.bootstrap_enrollment_marker() == Some(*current.marker_digest())
            }
            _ => {
                head_commitment(current) == Some(capsule.predecessor_commitment())
                    && capsule.bootstrap_enrollment_marker().is_none()
            }
        };
        if !linked {
            return Err(invalid("capsule.predecessor"));
        }
        // What is staged must be readable under the marker's binding in every later reconcile.
        C::decode_frame(frame, &C::marker_binding(current.marker()))
            .map_err(|_| invalid("capsule.binding"))?;
        let selected = current
            .select(state, kagemusha_wallet_boot_stamp_v1(boot))
            .map_err(|_| invalid("capsule.successor"))?;
        capsule
            .require_marker(selected.marker())
            .map_err(|_| invalid("capsule.marker"))?;
        let receipt_body = owner
            .receipt_body(capsule, capsule_digest)
            .map_err(|_| invalid("receipt_body"))?;
        Ok((selected, receipt_body))
    }

    /// A4-A12 after the request passed A0-A3.
    #[allow(clippy::too_many_arguments)]
    fn commit(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
        current: &KagemushaWalletDurableMarkerV1,
        request: &KagemushaWalletAdvanceRequestV1<C>,
        selected: KagemushaWalletMarkerRecordV1,
        receipt_body: Vec<u8>,
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
    ) -> Result<KagemushaWalletAdvanceOutcomeV1<R>, KagemushaWalletProviderErrorV1> {
        let operation_id = request.operation_id;
        let pending = KagemushaWalletAdvanceOutcomeV1::Pending { operation_id };
        let cleanup = request.capsule.capacity_class() == KagemushaWalletCapacityClassV1::Cleanup;
        let binding = C::marker_binding(current.record().marker());
        // A4: nothing is selected yet; a full disk is a capacity wait.
        let staged = self.with_ballast(cleanup, || {
            kagemusha_wallet_stage_capsule_v1(
                &self.store,
                current,
                boot,
                &request.capsule,
                &binding,
            )
        });
        let staged = match staged {
            Ok(staged) => staged,
            Err(KagemushaWalletProviderErrorV1::NoSpace) => {
                return Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
                    KagemushaWalletNotPerformedV1::CapacityWait,
                ));
            }
            Err(error @ KagemushaWalletProviderErrorV1::Uncertain(_)) => {
                self.note_pending(slot, error);
                return Ok(pending);
            }
            Err(error) => return Err(error),
        };
        // A5: the commit point.
        let published = self.with_ballast(cleanup, || {
            kagemusha_wallet_publish_marker_v1(&self.store, selected.clone())
        });
        let selected = match published {
            Ok(KagemushaWalletMarkerPublicationV1::Durable(selected)) => selected,
            Ok(KagemushaWalletMarkerPublicationV1::GenerationTaken) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
            Err(KagemushaWalletProviderErrorV1::NoSpace) => {
                // Nothing was selected: discard the staged copies now (the next reconcile
                // would discard them too, R7).
                let discarded = kagemusha_wallet_discard_staged_capsule_v1(
                    &self.store,
                    current,
                    staged.selected_generation,
                    &staged.capsule_digest,
                );
                if discarded.is_err() {
                    self.poison(slot);
                }
                return Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
                    KagemushaWalletNotPerformedV1::CapacityWait,
                ));
            }
            Err(error @ KagemushaWalletProviderErrorV1::Uncertain(_)) => {
                self.note_pending(slot, error);
                return Ok(pending);
            }
            Err(error) => return Err(error),
        };
        // A6-A12: the operation is performed and its debit irreversible. Every failure but
        // custody loss leaves it pending (with its reason recorded), never an error that a
        // caller could show as a rejected operation.
        match self.finish_selected(
            slot,
            owner,
            &selected,
            &request.capsule,
            &[current.record().generation()],
            boot,
            Some(receipt_body),
        ) {
            Ok(FinishedV1::Released(retained, _)) => {
                Ok(KagemushaWalletAdvanceOutcomeV1::Released {
                    retained: Box::new(retained),
                    resumed: false,
                })
            }
            Err(
                error @ (KagemushaWalletProviderErrorV1::LostCustody(_)
                | KagemushaWalletProviderErrorV1::KeyLost),
            ) => Err(error),
            Ok(FinishedV1::Stalled(_)) | Err(_) => Ok(pending),
        }
    }

    /// Finish a durable Selected marker (A6-A12; reconcile R9): retire `lower`, sign the
    /// receipt unless a valid record for the head exists, persist the record, publish and
    /// anchor the Released marker, retire the Selected marker and cache the result.
    ///
    /// `receipt_body` is the body asked in A2, when there is one; recovery asks the owner
    /// again. A stalled head stays cached as `Pending` (nothing was written after its
    /// adoption); any error poisons the slot. Both record their reason
    /// ([`Self::pending_reason`]).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_selected(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
        selected: &KagemushaWalletDurableMarkerV1,
        capsule: &C,
        lower: &[u128],
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
        receipt_body: Option<Vec<u8>>,
    ) -> Result<FinishedV1<R>, KagemushaWalletProviderErrorV1> {
        let result =
            self.finish_selected_inner(slot, owner, selected, capsule, lower, boot, receipt_body);
        match result {
            Ok(FinishedV1::Released(retained, released)) => {
                self.pending_reasons.remove(slot);
                self.remember(
                    slot,
                    released.clone(),
                    KagemushaWalletSlotStatusV1::Released(released.record().clone()),
                );
                Ok(FinishedV1::Released(retained, released))
            }
            Ok(FinishedV1::Stalled(reason)) => {
                self.note_pending(slot, reason);
                self.remember(
                    slot,
                    selected.clone(),
                    KagemushaWalletSlotStatusV1::Pending(selected.record().clone()),
                );
                Ok(FinishedV1::Stalled(reason))
            }
            Err(error) => {
                self.note_pending(slot, error);
                self.poison(slot);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_selected_inner(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        owner: &dyn KagemushaWalletTransitionOwnerV1<C, R>,
        selected: &KagemushaWalletDurableMarkerV1,
        capsule: &C,
        lower: &[u128],
        boot: &Result<[u8; 32], KagemushaWalletUnavailableV1>,
        receipt_body: Option<Vec<u8>>,
    ) -> Result<FinishedV1<R>, KagemushaWalletProviderErrorV1> {
        // A6: every older marker is retired before any signature.
        kagemusha_wallet_retire_markers_v1(&self.store, selected, lower)?;
        let capability =
            selected
                .selected_capability()
                .ok_or(KagemushaWalletProviderErrorV1::Invalid {
                    field: "marker.phase",
                })?;
        // The owner derives the receipt body from this capsule: it must be the capsule the
        // capability binds.
        let capsule_digest = *capability.capsule_digest();
        let frame = capsule
            .encode_frame()
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid { field: "capsule" })?;
        if C::frame_digest(&frame) != capsule_digest {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "capsule.digest",
            });
        }
        let record = selected.record();
        let binding = R::marker_binding(record.marker());
        let expectation = KagemushaWalletCompletionExpectationV1::Selected {
            selected_generation: capability.generation(),
            operation_id: *capability.operation_id(),
            capsule_digest,
        };
        // A7-A8: an existing valid record for this head was never released and is adopted
        // without a second signature.
        let existing =
            kagemusha_wallet_load_completion_v1::<F, R>(&self.store, slot, &expectation, &binding)?;
        let staged = if let Some(existing) = existing {
            self.with_ballast(true, || {
                kagemusha_wallet_stage_completion_v1(
                    &self.store,
                    &capability,
                    boot,
                    existing.value(),
                    &binding,
                )
            })?
        } else {
            let body = match receipt_body {
                Some(body) => body,
                None => match owner.receipt_body(capsule, &capsule_digest) {
                    Ok(body) => body,
                    Err(error) => return Ok(FinishedV1::Stalled(error)),
                },
            };
            // No record was found: that answer counts only while storage stayed available.
            self.require_storage()?;
            let signature = match kagemusha_wallet_sign_receipt_body_v1(
                &self.store,
                &self.platform,
                &capability,
                &body,
            ) {
                Ok(signature) => signature,
                Err(
                    error @ (KagemushaWalletSignErrorV1::Unavailable(_)
                    | KagemushaWalletSignErrorV1::KeyUnusable),
                ) => return Ok(FinishedV1::Stalled(error.into())),
                Err(error) => return Err(error.into()),
            };
            let completion = match owner.assemble(capsule, &capsule_digest, &signature) {
                Ok(completion) => completion,
                Err(error) => return Ok(FinishedV1::Stalled(error)),
            };
            self.with_ballast(true, || {
                kagemusha_wallet_stage_completion_v1(
                    &self.store,
                    &capability,
                    boot,
                    &completion,
                    &binding,
                )
            })?
        };
        // A9.
        let released_record = record.release(
            staged.completion_digest,
            kagemusha_wallet_boot_stamp_v1(boot),
        )?;
        let released = match self.with_ballast(true, || {
            kagemusha_wallet_publish_marker_v1(&self.store, released_record.clone())
        })? {
            KagemushaWalletMarkerPublicationV1::Durable(released) => released,
            KagemushaWalletMarkerPublicationV1::GenerationTaken => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(
                    KagemushaWalletUnavailableV1::Busy,
                ));
            }
        };
        // A10-A11: release point.
        kagemusha_wallet_raise_anchor_v1(&self.platform, released.record())?;
        kagemusha_wallet_retire_markers_v1(&self.store, &released, &[record.generation()])?;
        // A12.
        self.regrow_ballast();
        let retained = KagemushaWalletRetainedV1 {
            operation_id: *capability.operation_id(),
            capsule_digest,
            selected_generation: capability.generation(),
            completion_digest: staged.completion_digest,
            frame: staged.frame,
            record: staged.record,
        };
        Ok(FinishedV1::Released(retained, released))
    }

    // -----------------------------------------------------------------------------------
    // Capacity (spec §5.3; design A3, A12)
    // -----------------------------------------------------------------------------------

    /// A3: whether the operation may start. Growth needs free space for both capsule copies,
    /// its growth and the headroom beyond an intact ballast (regrown first when missing).
    /// Cleanup that lacks that space draws the ballast, which equals the worst-case Advance
    /// footprint, so outbox cleanup is never stranded by a full disk; without a ballast it
    /// waits.
    fn reserve_capacity(
        &self,
        class: KagemushaWalletCapacityClassV1,
        capsule_frame_bytes: usize,
        growth_bytes: u64,
    ) -> Result<bool, KagemushaWalletProviderErrorV1> {
        let overflow = KagemushaWalletProviderErrorV1::Invalid {
            field: "growth_bytes",
        };
        let copy = u64::try_from(capsule_frame_bytes)
            .ok()
            .and_then(|bytes| {
                bytes.checked_add(
                    u64::try_from(KAGEMUSHA_WALLET_FROZEN_FILE_OVERHEAD_BYTES_V1).ok()?,
                )
            })
            .ok_or(overflow)?;
        let needed = copy
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(growth_bytes))
            .and_then(|bytes| bytes.checked_add(KAGEMUSHA_WALLET_CAPACITY_HEADROOM_BYTES_V1))
            .ok_or(overflow)?;
        let available = || {
            self.store
                .available_bytes()
                .map_err(KagemushaWalletProviderErrorV1::Unavailable)
        };
        let ballast = self.ballast_present()?;
        match class {
            KagemushaWalletCapacityClassV1::Growth => {
                if !ballast && !self.write_ballast()? {
                    return Ok(false);
                }
                Ok(available()? >= needed)
            }
            KagemushaWalletCapacityClassV1::Cleanup => {
                if available()? >= needed {
                    return Ok(true);
                }
                if !ballast {
                    return Ok(false);
                }
                self.remove_ballast()?;
                Ok(true)
            }
        }
    }

    /// Run `operation`; when it fails for lack of space and `draw` allows it, remove the
    /// ballast and run it once more.
    pub(super) fn with_ballast<T>(
        &self,
        draw: bool,
        mut operation: impl FnMut() -> Result<T, KagemushaWalletProviderErrorV1>,
    ) -> Result<T, KagemushaWalletProviderErrorV1> {
        match operation() {
            Err(KagemushaWalletProviderErrorV1::NoSpace) if draw && self.ballast_present()? => {
                self.remove_ballast()?;
                operation()
            }
            other => other,
        }
    }

    /// Whether the ballast exists.
    pub(super) fn ballast_present(&self) -> Result<bool, KagemushaWalletProviderErrorV1> {
        Ok(
            kagemusha_wallet_list_dir_v1(&self.store, &KagemushaWalletCustodyDirV1::root())?
                .unwrap_or_default()
                .iter()
                .any(|entry| {
                    entry.kind == KagemushaWalletEntryKindV1::File
                        && entry.name == KAGEMUSHA_WALLET_BALLAST_NAME_V1
                }),
        )
    }

    /// Write the ballast create-new with random bytes; `false` when storage is too full.
    ///
    /// # Errors
    ///
    /// `Unavailable` when randomness or a write fails and `Uncertain` for an unknown outcome.
    pub(super) fn write_ballast(&self) -> Result<bool, KagemushaWalletProviderErrorV1> {
        let size = usize::try_from(self.options.ballast_bytes).map_err(|_| {
            KagemushaWalletProviderErrorV1::Invalid {
                field: "options.ballast_bytes",
            }
        })?;
        let mut bytes = vec![0_u8; size];
        rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|_| {
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(0))
        })?;
        match self.store.write_new(
            &KagemushaWalletCustodyDirV1::root(),
            &kagemusha_wallet_fixed_name_v1(KAGEMUSHA_WALLET_BALLAST_NAME_V1),
            &bytes,
        ) {
            KagemushaWalletPublishOutcomeV1::Published
            | KagemushaWalletPublishOutcomeV1::NotPublished(
                super::platform::KagemushaWalletNotPublishedV1::DestinationExists,
            ) => Ok(true),
            KagemushaWalletPublishOutcomeV1::NotPublished(
                super::platform::KagemushaWalletNotPublishedV1::NoSpace,
            ) => Ok(false),
            outcome => super::layout::kagemusha_wallet_require_published_v1(outcome).map(|()| true),
        }
    }

    fn remove_ballast(&self) -> Result<(), KagemushaWalletProviderErrorV1> {
        kagemusha_wallet_require_removed_v1(self.store.remove_file(
            &KagemushaWalletCustodyDirV1::root(),
            &kagemusha_wallet_fixed_name_v1(KAGEMUSHA_WALLET_BALLAST_NAME_V1),
        ))
    }

    /// A12: regrow a drawn ballast, best effort; a full disk leaves the next growth waiting.
    fn regrow_ballast(&self) {
        if matches!(self.ballast_present(), Ok(false)) {
            let _ = self.write_ballast();
        }
    }
}

#[cfg(test)]
#[path = "advance_tests.rs"]
mod tests;
