//! Durable monotone enrollment phase of one pre-key attempt (design §3.2 local-abandonment
//! safeguards).
//!
//! The phase is the evidence that tells a legitimately absent intent or marker from a lost one.
//! Each attempt keeps exactly one mandatory, replace-only pre-key record (`Phase`) under the
//! protected root, keyed by the attempt's request identity. Every version holds the immutable
//! attempt binding (request, slot, exact Client original and its nonce, accepted permit,
//! challenge, dates, key profile, creation policy and anchor kind) and the current phase:
//!
//! - `PreIntent`: created before the pre-key Slot selection, so a selected slot always has one.
//!   While the phase is `PreIntent` no intent exists and no key can have been generated;
//! - `IntentSelected { intent_digest }`: replaces it before the E2 intent is published;
//! - `MarkerSelected { intent_digest, marker_digest, payment_key }`: before the E4
//!   generation-zero marker is published;
//! - `MarkerCommitted { .., marker_file_digest }`: after the durable E4 marker and before the
//!   anchor is raised, the Enrolled step is exposed, E5 is retained or the marker is used.
//!
//! Each transition atomically replaces the exact current version (fresh inode, parent
//! synchronized) with its immediate successor; an uncertain replacement permits no following
//! effect, and every read durably adopts the visible version before it authorizes anything.
//! Once the Slot selection exists, a missing, unreadable or malformed phase is unavailable
//! custody, never `PreIntent`. An intent named by `IntentSelected` but absent is restored
//! create-new from the binding after its exact digest is verified; a generation-zero marker
//! named by `MarkerSelected` but absent is restored only with the exact witnessed key present,
//! no named anchor and no journal; a committed marker is never reconstructed. Restoration grants
//! no generation authority and never recreates a fresh-generation grant.

use iroha_data_model::kagemusha::{
    KagemushaDevicePublicKeyV1, KagemushaWalletEnrollmentChallengeV1,
};

use super::{
    KagemushaWalletProviderErrorV1,
    advance::KagemushaWalletAdvanceCapsuleV1,
    completion::KagemushaWalletCompletionFrameV1,
    decode_envelope_v1, encode_envelope_v1,
    enrollment::{
        KAGEMUSHA_WALLET_INTENT_FILE_VERSION_V1, KAGEMUSHA_WALLET_INTENT_MAX_BYTES_V1,
        KagemushaWalletEnrollmentDatesV1, KagemushaWalletIntentV1,
    },
    kagemusha_wallet_provider_digest_v1,
    layout::{KagemushaWalletCustodyDirV1, KagemushaWalletSlotIdV1, kagemusha_wallet_list_dir_v1},
    platform::{
        KagemushaWalletAnchorPolicyV1, KagemushaWalletEntryKindV1, KagemushaWalletFsV1,
        KagemushaWalletKeyGenerationPolicyV1, KagemushaWalletKeyProfileV1,
        KagemushaWalletPlatformV1, KagemushaWalletUnavailableV1,
    },
    prekey_custody::{PreKeyPublicationV1, PreKeyRecordV1, PreKeySlotSelectionV1},
    provider::KagemushaWalletProviderV1,
};

const PHASE_VERSION: u16 = 1;
const PHASE_MAX_BYTES: usize = 2_048;
const SLOT_SELECTION_MAX_BYTES: usize = 1_024;

/// Exact attempt binding. It is DATA retained by the exclusive owner; the enrollment owner
/// authenticates it against the retained Client, Accepted permit and Slot originals.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_advance_v1::EnrollmentPhaseBindingV1")]
pub struct KagemushaWalletEnrollmentBindingV1 {
    /// Exactly [`PHASE_VERSION`].
    pub(crate) version: u16,
    /// Pre-key request identity.
    pub(crate) request_id: [u8; 32],
    /// Selected slot.
    pub(crate) slot: [u8; 32],
    /// Digest of the exact retained Client original (the Fresh dispatch).
    pub(crate) client_digest: [u8; 32],
    /// Client nonce the Slot selection names.
    pub(crate) client_nonce: [u8; 32],
    /// Digest of the exact accepted permit original.
    pub(crate) permit_digest: [u8; 32],
    /// Issuer challenge of the accepted permit.
    pub(crate) challenge: KagemushaWalletEnrollmentChallengeV1,
    /// Original permit dates.
    pub(crate) dates: KagemushaWalletEnrollmentDatesV1,
    /// [`KagemushaWalletKeyProfileV1`] tag.
    pub(crate) profile: u8,
    /// [`KagemushaWalletKeyGenerationPolicyV1`] tag.
    pub(crate) generation_policy: u8,
    /// [`KagemushaWalletAnchorPolicyV1`] tag.
    pub(crate) anchor_kind: u8,
}

impl KagemushaWalletEnrollmentBindingV1 {
    /// Binding of a newly selected slot.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        request_id: [u8; 32],
        slot: [u8; 32],
        client_digest: [u8; 32],
        client_nonce: [u8; 32],
        permit_digest: [u8; 32],
        challenge: KagemushaWalletEnrollmentChallengeV1,
        dates: KagemushaWalletEnrollmentDatesV1,
        profile: KagemushaWalletKeyProfileV1,
        generation_policy: KagemushaWalletKeyGenerationPolicyV1,
        anchor_kind: KagemushaWalletAnchorPolicyV1,
    ) -> Self {
        Self {
            version: PHASE_VERSION,
            request_id,
            slot,
            client_digest,
            client_nonce,
            permit_digest,
            challenge,
            dates,
            profile: profile.tag(),
            generation_policy: generation_policy.tag(),
            anchor_kind: anchor_kind.tag(),
        }
    }

    fn validate(&self, scheme_id: &[u8; 32]) -> Result<(), KagemushaWalletProviderErrorV1> {
        self.validate_structure()?;
        if self.challenge.scheme_id != *scheme_id {
            return Err(corrupt());
        }
        Ok(())
    }

    // Root inventory may contain another scheme's intact custody. Structural validity is
    // not authority to adopt or operate it; selected phase APIs still require their scheme.
    fn validate_structure(&self) -> Result<(), KagemushaWalletProviderErrorV1> {
        if self.version != PHASE_VERSION
            || self.request_id == [0; 32]
            || self.slot == [0; 32]
            || self.client_digest == [0; 32]
            || self.client_nonce == [0; 32]
            || self.permit_digest == [0; 32]
            || self.challenge.validate().is_err()
            || !self.dates.is_valid()
            || KagemushaWalletKeyProfileV1::from_tag(self.profile).is_none()
            || KagemushaWalletKeyGenerationPolicyV1::from_tag(self.generation_policy).is_none()
            || KagemushaWalletAnchorPolicyV1::from_tag(self.anchor_kind).is_none()
        {
            return Err(corrupt());
        }
        Ok(())
    }

    /// The exact E2 intent this binding selects; deterministic, so it can be restored.
    pub(crate) fn intent(&self) -> KagemushaWalletIntentV1 {
        KagemushaWalletIntentV1 {
            version: KAGEMUSHA_WALLET_INTENT_FILE_VERSION_V1,
            slot: self.slot,
            challenge: self.challenge,
            anchor_kind: self.anchor_kind,
            profile: self.profile,
            generation_policy: self.generation_policy,
            dates: self.dates,
        }
    }
}

/// Digest of the exact retained pre-key Client original a phase names.
pub fn kagemusha_wallet_prekey_client_digest_v1(client: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("enrollment-pre-key-client", client)
}

/// Digest of the exact accepted permit original a phase names.
pub fn kagemusha_wallet_prekey_permit_digest_v1(accepted: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("enrollment-pre-key-permit", accepted)
}

/// Digest of the exact intent envelope a phase names.
pub(super) fn kagemusha_wallet_intent_digest_v1(
    intent: &KagemushaWalletIntentV1,
) -> Result<[u8; 32], KagemushaWalletProviderErrorV1> {
    Ok(kagemusha_wallet_provider_digest_v1(
        "enrollment-phase-intent",
        &encode_envelope_v1(intent, KAGEMUSHA_WALLET_INTENT_MAX_BYTES_V1)?,
    ))
}

/// Current monotone phase of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KagemushaWalletEnrollmentPhaseV1 {
    /// No intent was selected: no intent exists and no key was generated.
    PreIntent,
    /// The exact intent was selected before its publication.
    IntentSelected {
        /// Digest of the exact intent envelope.
        intent_digest: [u8; 32],
    },
    /// The generation-zero marker of this key was selected before its publication.
    MarkerSelected {
        /// Digest of the exact intent envelope.
        intent_digest: [u8; 32],
        /// G1 digest of the generation-zero marker.
        marker_digest: [u8; 32],
        /// Payment key the marker names.
        payment_key: KagemushaDevicePublicKeyV1,
    },
    /// The generation-zero marker was durable before any use; it is never reconstructed.
    MarkerCommitted {
        /// Digest of the exact intent envelope.
        intent_digest: [u8; 32],
        /// G1 digest of the generation-zero marker.
        marker_digest: [u8; 32],
        /// Payment key the marker names.
        payment_key: KagemushaDevicePublicKeyV1,
        /// Digest of the exact durable marker file.
        marker_file_digest: [u8; 32],
    },
}

impl KagemushaWalletEnrollmentPhaseV1 {
    /// Whether a marker was ever selected for the attempt.
    pub(crate) const fn marker_selected(&self) -> bool {
        matches!(
            self,
            Self::MarkerSelected { .. } | Self::MarkerCommitted { .. }
        )
    }

    /// Digest of the selected intent, once selected.
    pub(crate) const fn intent_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::PreIntent => None,
            Self::IntentSelected { intent_digest }
            | Self::MarkerSelected { intent_digest, .. }
            | Self::MarkerCommitted { intent_digest, .. } => Some(*intent_digest),
        }
    }

    const fn rank(&self) -> u8 {
        match self {
            Self::PreIntent => 0,
            Self::IntentSelected { .. } => 1,
            Self::MarkerSelected { .. } => 2,
            Self::MarkerCommitted { .. } => 3,
        }
    }
}

/// Binding and current phase of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletEnrollmentPhaseStateV1 {
    pub(crate) binding: KagemushaWalletEnrollmentBindingV1,
    pub(crate) phase: KagemushaWalletEnrollmentPhaseV1,
}

/// One complete version of the replace-only phase record.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_advance_v1::EnrollmentPhaseV1")]
struct PhaseRecordV1 {
    version: u16,
    binding: KagemushaWalletEnrollmentBindingV1,
    /// 0 `PreIntent`, 1 `IntentSelected`, 2 `MarkerSelected`, 3 `MarkerCommitted`.
    phase: u8,
    /// Zero before `IntentSelected`.
    intent_digest: [u8; 32],
    /// Zero before `MarkerSelected`.
    marker_digest: [u8; 32],
    /// `Some` exactly from `MarkerSelected` on.
    payment_key: Option<KagemushaDevicePublicKeyV1>,
    /// Zero before `MarkerCommitted`.
    marker_file_digest: [u8; 32],
}

impl PhaseRecordV1 {
    fn new(state: &KagemushaWalletEnrollmentPhaseStateV1) -> Self {
        use KagemushaWalletEnrollmentPhaseV1 as Phase;
        let mut record = Self {
            version: PHASE_VERSION,
            binding: state.binding,
            phase: state.phase.rank(),
            intent_digest: [0; 32],
            marker_digest: [0; 32],
            payment_key: None,
            marker_file_digest: [0; 32],
        };
        match state.phase {
            Phase::PreIntent => {}
            Phase::IntentSelected { intent_digest } => record.intent_digest = intent_digest,
            Phase::MarkerSelected {
                intent_digest,
                marker_digest,
                payment_key,
            } => {
                record.intent_digest = intent_digest;
                record.marker_digest = marker_digest;
                record.payment_key = Some(payment_key);
            }
            Phase::MarkerCommitted {
                intent_digest,
                marker_digest,
                payment_key,
                marker_file_digest,
            } => {
                record.intent_digest = intent_digest;
                record.marker_digest = marker_digest;
                record.payment_key = Some(payment_key);
                record.marker_file_digest = marker_file_digest;
            }
        }
        record
    }

    /// Strict projection: every field outside the current phase is zero or absent, every
    /// field inside it is selected.
    fn state(
        &self,
    ) -> Result<KagemushaWalletEnrollmentPhaseStateV1, KagemushaWalletProviderErrorV1> {
        use KagemushaWalletEnrollmentPhaseV1 as Phase;
        let phase = match (self.phase, self.payment_key) {
            (0, None) => Phase::PreIntent,
            (1, None) => Phase::IntentSelected {
                intent_digest: self.intent_digest,
            },
            (2, Some(payment_key)) => Phase::MarkerSelected {
                intent_digest: self.intent_digest,
                marker_digest: self.marker_digest,
                payment_key,
            },
            (3, Some(payment_key)) => Phase::MarkerCommitted {
                intent_digest: self.intent_digest,
                marker_digest: self.marker_digest,
                payment_key,
                marker_file_digest: self.marker_file_digest,
            },
            _ => return Err(corrupt()),
        };
        let state = KagemushaWalletEnrollmentPhaseStateV1 {
            binding: self.binding,
            phase,
        };
        let selected = |digest: [u8; 32]| digest != [0; 32];
        let complete = match phase {
            Phase::PreIntent => true,
            Phase::IntentSelected { intent_digest } => selected(intent_digest),
            Phase::MarkerSelected {
                intent_digest,
                marker_digest,
                ..
            } => selected(intent_digest) && selected(marker_digest),
            Phase::MarkerCommitted {
                intent_digest,
                marker_digest,
                marker_file_digest,
                ..
            } => selected(intent_digest) && selected(marker_digest) && selected(marker_file_digest),
        };
        if self.version != PHASE_VERSION || Self::new(&state) != *self || !complete {
            return Err(corrupt());
        }
        Ok(state)
    }
}

fn corrupt() -> KagemushaWalletProviderErrorV1 {
    KagemushaWalletProviderErrorV1::UnavailableCustodyData {
        object: "enrollment phase",
    }
}

fn busy() -> KagemushaWalletProviderErrorV1 {
    KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy)
}

fn encode_phase(
    state: &KagemushaWalletEnrollmentPhaseStateV1,
) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
    encode_envelope_v1(&PhaseRecordV1::new(state), PHASE_MAX_BYTES)
}

/// Encoded phase record of `state` (tests construct exact versions with it).
#[cfg(test)]
pub(super) fn test_phase_record(state: &KagemushaWalletEnrollmentPhaseStateV1) -> Vec<u8> {
    encode_phase(state).expect("phase record")
}

/// Decoded phase record (tests).
#[cfg(test)]
pub(super) fn test_decode_phase_record(bytes: &[u8]) -> KagemushaWalletEnrollmentPhaseStateV1 {
    decode_envelope_v1::<PhaseRecordV1>(bytes, PHASE_MAX_BYTES)
        .expect("phase record")
        .state()
        .expect("phase state")
}

/// Request identity named by the pre-key record file `name` of `role`, when it is one.
fn prekey_request(
    name: &str,
    role: PreKeyRecordV1,
) -> Result<Option<[u8; 32]>, KagemushaWalletProviderErrorV1> {
    let suffix = format!("-{}.norito", role.role());
    let Some(hex_id) = name
        .strip_prefix("prekey-")
        .and_then(|rest| rest.strip_suffix(suffix.as_str()))
    else {
        return Ok(None);
    };
    let mut id = [0; 32];
    hex::decode_to_slice(hex_id, &mut id).map_err(|_| corrupt())?;
    Ok(Some(id))
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Anchor kind this platform records for new slots.
    pub(crate) fn anchor_policy(&self) -> KagemushaWalletAnchorPolicyV1 {
        self.platform.anchor_policy()
    }

    /// Structurally read the visible phase without adopting it. Current-scheme admission
    /// belongs to `adopted_phase`; inventory alone grants no authority over this attempt.
    fn read_phase(
        &self,
        request_id: &[u8; 32],
    ) -> Result<
        Option<(Vec<u8>, KagemushaWalletEnrollmentPhaseStateV1)>,
        KagemushaWalletProviderErrorV1,
    > {
        let Some(bytes) = self.prekey_read(request_id, PreKeyRecordV1::Phase)? else {
            return Ok(None);
        };
        let record: PhaseRecordV1 =
            decode_envelope_v1(&bytes, PHASE_MAX_BYTES).map_err(|_| corrupt())?;
        let state = record.state()?;
        state.binding.validate_structure()?;
        if state.binding.request_id != *request_id {
            return Err(corrupt());
        }
        Ok(Some((bytes, state)))
    }

    /// The durable phase of `request_id`; `None` only when the attempt has no phase record at
    /// all. The visible version is durably adopted (republished on a fresh inode once per
    /// process) before it is returned, so a version left visible by an uncertain replacement or
    /// a lost writeback never authorizes a following effect.
    ///
    /// # Errors
    /// `Unavailable`/`Uncertain` for unreadable storage or an unknown adoption;
    /// `UnavailableCustodyData` for a malformed or foreign record.
    pub(crate) fn enrollment_phase(
        &self,
        request_id: &[u8; 32],
    ) -> Result<Option<KagemushaWalletEnrollmentPhaseStateV1>, KagemushaWalletProviderErrorV1> {
        Ok(self.adopted_phase(request_id)?.map(|(_, state)| state))
    }

    fn adopted_phase(
        &self,
        request_id: &[u8; 32],
    ) -> Result<
        Option<(Vec<u8>, KagemushaWalletEnrollmentPhaseStateV1)>,
        KagemushaWalletProviderErrorV1,
    > {
        let Some((bytes, state)) = self.read_phase(request_id)? else {
            return Ok(None);
        };
        state.binding.validate(&self.scheme_id)?;
        self.prekey_adopt(request_id, &[PreKeyRecordV1::Phase])?;
        if self
            .read_phase(request_id)?
            .map(|(adopted, _)| adopted)
            .as_ref()
            != Some(&bytes)
        {
            return Err(busy());
        }
        Ok(Some((bytes, state)))
    }

    /// Create the attempt's `PreIntent` phase before its Slot selection; an existing phase of
    /// the same request wins and its binding is returned, so an interrupted selection reuses
    /// the slot it already named.
    ///
    /// # Errors
    /// Invalid bindings, unavailable or uncertain storage, or a malformed existing record.
    pub(crate) fn select_enrollment_binding(
        &mut self,
        binding: &KagemushaWalletEnrollmentBindingV1,
    ) -> Result<KagemushaWalletEnrollmentBindingV1, KagemushaWalletProviderErrorV1> {
        binding.validate(&self.scheme_id)?;
        let bytes = encode_phase(&KagemushaWalletEnrollmentPhaseStateV1 {
            binding: *binding,
            phase: KagemushaWalletEnrollmentPhaseV1::PreIntent,
        })?;
        match self.prekey_retain(&binding.request_id, PreKeyRecordV1::Phase, &bytes)? {
            PreKeyPublicationV1::Published | PreKeyPublicationV1::Existing(_) => {}
        }
        Ok(self
            .enrollment_phase(&binding.request_id)?
            .ok_or_else(corrupt)?
            .binding)
    }

    /// Replace the durable current phase with `next(current)`: `None` keeps it (an exact
    /// retry); a successor must be the immediate next phase with the same binding.
    fn advance_phase(
        &mut self,
        request_id: &[u8; 32],
        next: impl FnOnce(
            &KagemushaWalletEnrollmentPhaseStateV1,
        ) -> Result<
            Option<KagemushaWalletEnrollmentPhaseV1>,
            KagemushaWalletProviderErrorV1,
        >,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let (expected, current) = self.adopted_phase(request_id)?.ok_or_else(corrupt)?;
        let Some(phase) = next(&current)? else {
            return Ok(());
        };
        if phase.rank() != current.phase.rank() + 1 {
            return Err(corrupt());
        }
        // Enrollment phase publications run in the enrollment owner, where no embedder call has
        // staged archive records of the slot (records are staged only under a committed marker).
        debug_assert!(
            self.archive_batch_is_empty(&KagemushaWalletSlotIdV1(current.binding.slot)),
            "enrollment phase publication with staged archive records"
        );
        let replacement = encode_phase(&KagemushaWalletEnrollmentPhaseStateV1 {
            binding: current.binding,
            phase,
        })?;
        self.prekey_replace(request_id, PreKeyRecordV1::Phase, &expected, &replacement)?;
        // A slot verified under the previous version is now verified under this one.
        if let Some(verified) = self
            .slot_phases
            .borrow_mut()
            .get_mut(&KagemushaWalletSlotIdV1(current.binding.slot))
            .filter(|(id, _)| id == request_id)
        {
            verified.1[0] = replacement;
        }
        Ok(())
    }

    /// Select the exact E2 intent before its publication. Idempotent for the same intent; any
    /// other intent or a later phase that names another intent is unavailable custody.
    ///
    /// # Errors
    /// A foreign intent, inconsistent phase, unavailable or uncertain storage.
    pub(super) fn select_intent_phase(
        &mut self,
        request_id: &[u8; 32],
        intent: &KagemushaWalletIntentV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let intent_digest = kagemusha_wallet_intent_digest_v1(intent)?;
        self.advance_phase(request_id, |current| {
            if current.binding.intent() != *intent {
                return Err(KagemushaWalletProviderErrorV1::Invalid {
                    field: "enrollment phase intent",
                });
            }
            match current.phase {
                KagemushaWalletEnrollmentPhaseV1::PreIntent => {
                    Ok(Some(KagemushaWalletEnrollmentPhaseV1::IntentSelected {
                        intent_digest,
                    }))
                }
                phase if phase.intent_digest() == Some(intent_digest) => Ok(None),
                _ => Err(corrupt()),
            }
        })
    }

    /// Select the generation-zero marker of `payment_key` before its publication.
    ///
    /// # Errors
    /// An unselected intent, another key or marker, unavailable or uncertain storage.
    pub(super) fn select_marker_phase(
        &mut self,
        request_id: &[u8; 32],
        marker_digest: [u8; 32],
        payment_key: KagemushaDevicePublicKeyV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        self.advance_phase(request_id, |current| match current.phase {
            KagemushaWalletEnrollmentPhaseV1::IntentSelected { intent_digest } => {
                Ok(Some(KagemushaWalletEnrollmentPhaseV1::MarkerSelected {
                    intent_digest,
                    marker_digest,
                    payment_key,
                }))
            }
            KagemushaWalletEnrollmentPhaseV1::MarkerSelected {
                marker_digest: selected,
                payment_key: key,
                ..
            } if selected == marker_digest && key == payment_key => Ok(None),
            _ => Err(corrupt()),
        })
    }

    /// Commit the durable generation-zero marker before the anchor is raised, the Enrolled
    /// step is exposed or the marker is used.
    ///
    /// # Errors
    /// An unselected or different marker, a changed committed file, unavailable or uncertain
    /// storage.
    pub(super) fn commit_marker_phase(
        &mut self,
        request_id: &[u8; 32],
        marker_digest: [u8; 32],
        marker_file_digest: [u8; 32],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        self.advance_phase(request_id, |current| match current.phase {
            KagemushaWalletEnrollmentPhaseV1::MarkerSelected {
                intent_digest,
                marker_digest: selected,
                payment_key,
            } if selected == marker_digest => {
                Ok(Some(KagemushaWalletEnrollmentPhaseV1::MarkerCommitted {
                    intent_digest,
                    marker_digest,
                    payment_key,
                    marker_file_digest,
                }))
            }
            KagemushaWalletEnrollmentPhaseV1::MarkerCommitted {
                marker_digest: selected,
                marker_file_digest: committed,
                ..
            } if selected == marker_digest && committed == marker_file_digest => Ok(None),
            _ => Err(corrupt()),
        })
    }

    /// Request identity of the attempt whose phase selected `slot`, checked against the
    /// identity the caller carries. Every marker or intent publication of a phased slot uses
    /// it, whichever path (begin, resume, retained reply, restoration) reaches the publication.
    ///
    /// # Errors
    /// A carried identity without the matching phase, and the errors of
    /// [`Self::enrollment_phase_for_slot`].
    pub(super) fn slot_phase_request(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        carried: Option<[u8; 32]>,
    ) -> Result<Option<[u8; 32]>, KagemushaWalletProviderErrorV1> {
        let found = self
            .enrollment_phase_for_slot(slot)?
            .map(|state| state.binding.request_id);
        match (carried, found) {
            (Some(carried), Some(found)) if carried == found => Ok(Some(carried)),
            (Some(_), _) => Err(corrupt()),
            (None, found) => Ok(found),
        }
    }

    /// Phase of the attempt that selected `slot`, found among every retained phase and Slot
    /// selection under the protected root. A Slot selection is published only after its
    /// phase, so a Slot selection without its phase, or naming another slot, permit or
    /// creation policy than its phase, is lost custody for every slot. The attempt that
    /// selected `slot` must also keep its Slot selection, Client and Accepted permit originals,
    /// the latter exactly the permit its phase names. `None` only when no retained phase names
    /// the slot: production creation always selects one (`begin_enrollment_checked`), so only
    /// provider simulator fixtures create such slots.
    ///
    /// # Errors
    /// Unreadable storage, a corrupt or orphaned record, two phases naming the slot, missing
    /// originals or inconsistent phase custody.
    pub(crate) fn enrollment_phase_for_slot(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<Option<KagemushaWalletEnrollmentPhaseStateV1>, KagemushaWalletProviderErrorV1> {
        let Some((state, originals)) = self.read_phase_originals_for_slot(slot)? else {
            return Ok(None);
        };
        state.binding.validate(&self.scheme_id)?;
        let id = state.binding.request_id;
        // Only this provider's selected scheme is adopted or cached. Other schemes were
        // structurally checked above, never admitted as this wallet's custody.
        let (bytes, adopted) = self.adopted_phase(&id)?.ok_or_else(corrupt)?;
        if adopted != state {
            return Err(busy());
        }
        self.prekey_adopt(
            &id,
            &[
                PreKeyRecordV1::Client,
                PreKeyRecordV1::Accepted,
                PreKeyRecordV1::Slot,
            ],
        )?;
        for (role, original) in [
            PreKeyRecordV1::Phase,
            PreKeyRecordV1::Client,
            PreKeyRecordV1::Accepted,
            PreKeyRecordV1::Slot,
        ]
        .into_iter()
        .zip([&bytes, &originals[0], &originals[1], &originals[2]])
        {
            if self.prekey_read(&id, role)?.as_ref() != Some(original) {
                return Err(busy());
            }
        }
        let [client, accepted, selection] = originals;
        self.slot_phases
            .borrow_mut()
            .insert(*slot, (id, [bytes, client, accepted, selection]));
        Ok(Some(state))
    }

    // Read-only inventory. Every Phase and Slot is checked, including malformed/orphaned
    // records outside the requested slot. No foreign original is adopted or cached.
    fn read_phase_originals_for_slot(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<
        Option<(KagemushaWalletEnrollmentPhaseStateV1, [Vec<u8>; 3])>,
        KagemushaWalletProviderErrorV1,
    > {
        let entries =
            kagemusha_wallet_list_dir_v1(&self.store, &KagemushaWalletCustodyDirV1::root())?
                .unwrap_or_default();
        let mut phases = std::collections::BTreeMap::new();
        let mut selections = std::collections::BTreeSet::new();
        for entry in &entries {
            if let Some(id) = prekey_request(&entry.name, PreKeyRecordV1::Phase)? {
                if entry.kind != KagemushaWalletEntryKindV1::File {
                    return Err(corrupt());
                }
                let (_, state) = self.read_phase(&id)?.ok_or_else(busy)?;
                phases.insert(id, state);
            } else if let Some(id) = prekey_request(&entry.name, PreKeyRecordV1::Slot)? {
                selections.insert(id);
            }
        }
        // Every Slot selection names exactly the slot, permit and creation policy of its phase.
        for id in &selections {
            let bytes = self
                .prekey_read(id, PreKeyRecordV1::Slot)?
                .ok_or_else(busy)?;
            if bytes.is_empty() || bytes.len() > SLOT_SELECTION_MAX_BYTES {
                return Err(corrupt());
            }
            let selection: PreKeySlotSelectionV1 = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(SLOT_SELECTION_MAX_BYTES),
            )
            .map_err(|_| corrupt())?;
            let binding = &phases.get(id).ok_or_else(corrupt)?.binding;
            if selection.version != 1
                || selection.client_nonce != binding.client_nonce
                || selection.slot != binding.slot
                || selection.permit_digest != binding.permit_digest
                || selection.generation_policy != binding.generation_policy
            {
                return Err(corrupt());
            }
        }
        let mut found = None;
        for (id, state) in &phases {
            if state.binding.slot == slot.0 && found.replace(*id).is_some() {
                return Err(corrupt());
            }
        }
        let Some(id) = found else {
            return Ok(None);
        };
        // The attempt that selected this slot keeps exactly the originals its phase names.
        let binding = phases[&id].binding;
        let client = self.prekey_read(&id, PreKeyRecordV1::Client)?;
        let accepted = self.prekey_read(&id, PreKeyRecordV1::Accepted)?;
        let selection = self.prekey_read(&id, PreKeyRecordV1::Slot)?;
        if !selections.contains(&id)
            || client
                .as_deref()
                .map(kagemusha_wallet_prekey_client_digest_v1)
                != Some(binding.client_digest)
            || accepted
                .as_deref()
                .map(kagemusha_wallet_prekey_permit_digest_v1)
                != Some(binding.permit_digest)
        {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "selected pre-key originals",
            });
        }
        let (Some(client), Some(accepted), Some(selection)) = (client, accepted, selection) else {
            return Err(busy());
        };
        Ok(Some((phases[&id], [client, accepted, selection])))
    }

    /// Check an intent's exact retained phase and originals for inventory only. For a foreign
    /// intent, verify the permit under the retained Client's scheme and certificate; this does
    /// not select an old trusted runtime or grant authority to reconcile, sign or replace
    /// custody. Selected-slot APIs still require this provider's scheme.
    ///
    /// # Errors
    /// Missing, malformed, changed or inconsistent Phase/Slot/Client/Accepted/intent records,
    /// an invalid retained permit signature, or any unavailable storage read.
    pub(super) fn require_enrollment_search_intent(
        &self,
        slot: &KagemushaWalletSlotIdV1,
        intent: &KagemushaWalletIntentV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        use crate::kagemusha_wallet_enrollment_v1::PreKeyDispatchV1;
        use iroha_data_model::kagemusha::{
            KagemushaEnrollmentPermitPurposeV1, KagemushaEnrollmentPermitV1,
        };

        let (state, [client, accepted, selection]) = self
            .read_phase_originals_for_slot(slot)?
            .ok_or_else(corrupt)?;
        if state.binding.intent() != *intent
            || state.phase.intent_digest() != Some(kagemusha_wallet_intent_digest_v1(intent)?)
        {
            return Err(corrupt());
        }
        if intent.challenge.scheme_id != self.scheme_id {
            let dispatch = PreKeyDispatchV1::decode(&client).map_err(|_| corrupt())?;
            let permit = KagemushaEnrollmentPermitV1::decode_canonical(
                &accepted,
                &dispatch.scheme,
                &dispatch.enrollment_certificate,
            )
            .map_err(|_| corrupt())?;
            dispatch
                .require_permit_selection(&permit)
                .map_err(|_| corrupt())?;
            if dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
                || dispatch.previous_permit.is_some()
                || dispatch.request_id != state.binding.request_id
                || dispatch.client_nonce != state.binding.client_nonce
                || intent.profile
                    != crate::kagemusha_wallet_enrollment_v1::platform_key_profile(
                        &dispatch.policy.platform,
                    )
                    .tag()
                || permit.body.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
                || permit.body.challenge != intent.challenge
                || permit.body.created_at_ms != intent.dates.issued_at_ms
                || permit.body.expires_at_ms != intent.dates.expires_at_ms
            {
                return Err(corrupt());
            }
        }
        // Storage availability and unchanged originals bracket this read-only classification.
        let Some((after, originals)) = self.read_phase_originals_for_slot(slot)? else {
            return Err(busy());
        };
        if after != state || originals != [client, accepted, selection] {
            return Err(busy());
        }
        Ok(())
    }

    /// Whether the phase this process last verified for `slot` is still exactly the visible
    /// one; a slot without a verified phase answers `true`. Cached returns use it, so a changed
    /// or lost phase sends the slot back through full reconciliation.
    ///
    /// # Errors
    /// Unreadable storage.
    pub(super) fn verified_phase_unchanged(
        &self,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<bool, KagemushaWalletProviderErrorV1> {
        let Some((id, verified)) = self.slot_phases.borrow().get(slot).cloned() else {
            return Ok(true);
        };
        // The phase and every original it names: Client, Accepted permit and Slot selection.
        for (role, verified) in [
            PreKeyRecordV1::Phase,
            PreKeyRecordV1::Client,
            PreKeyRecordV1::Accepted,
            PreKeyRecordV1::Slot,
        ]
        .into_iter()
        .zip(verified.iter())
        {
            if self.prekey_read(&id, role)?.as_ref() != Some(verified) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
