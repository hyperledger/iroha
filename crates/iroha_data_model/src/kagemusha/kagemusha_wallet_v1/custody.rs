//! Local custody objects of the durable state provider (§4, design §5 with C3).
//!
//! The provider keeps one durable current marker per payment key, a frozen recovery capsule
//! per selected head and a separate completion record holding the receipt and the exact
//! released output bytes. These objects are local: they never travel between peers, and their
//! digests are taken over complete canonical Norito frames. The capsule is frozen before the
//! receipt is signed, so its output descriptor is receipt-free.
//!
//! Design §5 lists the terminal marker `reason`, the output descriptor `kind` and the retained
//! input `role` as `u8` values. As for the `RefreshPolicy` update kind (design C1), each is a
//! typed Norito enum whose wire tag equals the listed value, so an undefined value fails
//! canonical decoding instead of reaching validation; the `output` transcript carries the
//! one-byte tag. Their frames therefore carry Norito's four-byte enum tag, which the marker
//! and capsule digests cover. The retained-input role table (tags 1 to 10) is fixed here; the
//! vectors file pins every tag.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1, KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1, KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1, KAGEMUSHA_WALLET_VERSION_V1,
    KagemushaWalletPolicyUpdateKindV1, KagemushaWalletQuotaRefreshWitnessV1, WalletResult,
    WalletVersionsV1, decode_frame_v1,
    digest::{KagemushaWalletDigestRoleV1 as Role, WalletTranscriptV1, kagemusha_wallet_digest_v1},
    encode_frame_v1,
    identity::{
        KagemushaWalletCredentialV1, KagemushaWalletEnrollmentChallengeV1,
        kagemusha_wallet_enrollment_id_v1, kagemusha_wallet_id_v1,
    },
    invalid_v1, is_zero_v1,
    keys::KagemushaDevicePublicKeyV1,
    messages::KagemushaWalletPaymentV1,
    overflow_v1,
    poseidon::KagemushaWalletIndexedOpeningV1,
    require_canonical_field_v1, require_nonzero_field_v1, require_nonzero_v1, require_scheme_v1,
    require_version_v1,
    state::{
        KagemushaWalletEffectV1, KagemushaWalletLineageSlotV1, KagemushaWalletLineageV1,
        KagemushaWalletOperationKindV1, KagemushaWalletPackageDigestsV1, KagemushaWalletPackageV1,
        KagemushaWalletReceiptV1, KagemushaWalletStateCommitmentV1, KagemushaWalletStateV1,
        KagemushaWalletStatementV1, KagemushaWalletStepProofV1, kagemusha_wallet_proof_digest_v1,
    },
};

#[cfg(test)]
#[path = "custody_tests.rs"]
pub(super) mod custody_tests;

#[cfg(test)]
#[path = "capsule_commitment_tests.rs"]
mod capsule_commitment_tests;

const DIGEST_BYTES: usize = 32;

/// Exact `output` transcript bytes:
/// `u8 kind || statement_digest || proof_digest || payment_digest or zero`.
pub const KAGEMUSHA_WALLET_OUTPUT_TRANSCRIPT_BYTES_V1: usize = 1 + 3 * DIGEST_BYTES;

// ---------------------------------------------------------------------------------------
// Provider marker (§§3.2, 4.2, design §5.1)
// ---------------------------------------------------------------------------------------

/// Reason a marker became terminal.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletTerminalReasonV1"
)]
pub enum KagemushaWalletTerminalReasonV1 {
    /// Unused enrollment abandoned before Bootstrap committed (§3.2).
    #[codec(index = 1)]
    Abandoned,
    /// Deliberate permanent custody deletion (§6.3).
    #[codec(index = 2)]
    CustodyDeleted,
}

impl KagemushaWalletTerminalReasonV1 {
    /// Every reason, in tag order.
    pub const ALL: [Self; 2] = [Self::Abandoned, Self::CustodyDeleted];

    /// Tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Abandoned => 1,
            Self::CustodyDeleted => 2,
        }
    }
}

/// State selected by one provider marker generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletMarkerStateV1"
)]
#[repr(align(16))]
pub enum KagemushaWalletMarkerStateV1 {
    /// Generation-0 enrollment marker, written before the credential request.
    #[codec(index = 1)]
    Enrollment {
        /// Enrollment challenge digest.
        challenge_digest: [u8; 32],
        /// Enrollment identity of the payment key under that challenge.
        enrollment_id: [u8; 32],
    },
    /// Selected head of one committed transition.
    #[codec(index = 2)]
    Head {
        /// Sequence of the selected head.
        sequence: u128,
        /// Operation identity of the transition that selected it.
        operation_id: [u8; 32],
        /// Selected state commitment.
        head: KagemushaWalletStateCommitmentV1,
        /// Digest of the head's frozen recovery capsule.
        capsule_digest: [u8; 32],
        /// Digest of the predecessor's capsule; zero for Bootstrap.
        predecessor_capsule_digest: [u8; 32],
    },
    /// Terminal marker: the incarnation is never initialized or advanced again.
    #[codec(index = 3)]
    Terminal {
        /// Reason.
        reason: KagemushaWalletTerminalReasonV1,
        /// Capsule digest of the last head; zero after abandonment.
        last_capsule_digest: [u8; 32],
    },
}

impl KagemushaWalletMarkerStateV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Enrollment { .. } => 1,
            Self::Head { .. } => 2,
            Self::Terminal { .. } => 3,
        }
    }
}

/// Durable non-backup provider marker of one payment key (§4.2).
///
/// Its digest is `H("marker", canonical frame)`; the Bootstrap effect binds the digest of the
/// generation-0 enrollment marker (design C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletMarkerV1")]
#[repr(align(16))]
pub struct KagemushaWalletMarkerV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Enrolled scheme.
    pub scheme_id: [u8; 32],
    /// Enrolled asset scope digest.
    pub asset_digest: [u8; 32],
    /// Wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Hardware-backed payment key.
    pub payment_key: KagemushaDevicePublicKeyV1,
    /// Marker generation; zero only for the enrollment marker.
    pub generation: u128,
    /// Selected state.
    pub state: KagemushaWalletMarkerStateV1,
}

impl KagemushaWalletMarkerV1 {
    /// Generation-0 enrollment marker of `payment_key` under `challenge` (§3.2).
    ///
    /// # Errors
    ///
    /// Rejects an invalid challenge or key.
    pub fn enrollment(
        challenge: &KagemushaWalletEnrollmentChallengeV1,
        payment_key: KagemushaDevicePublicKeyV1,
    ) -> WalletResult<Self> {
        challenge.validate()?;
        payment_key.validate()?;
        let marker = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: challenge.scheme_id,
            asset_digest: challenge.asset_digest,
            wallet_id: challenge.wallet_id(&payment_key),
            payment_key,
            generation: 0,
            state: KagemushaWalletMarkerStateV1::Enrollment {
                challenge_digest: challenge.challenge_digest(),
                enrollment_id: challenge.enrollment_id(&payment_key),
            },
        };
        marker.validate()?;
        Ok(marker)
    }

    /// Validate the marker's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, an invalid key; an enrollment marker that is
    /// not generation 0 or whose enrollment or wallet identity does not recompute; a head or
    /// terminal marker at generation 0; an incomplete head, zero head digests, or a
    /// predecessor capsule that is present exactly when the head is Bootstrap; and a terminal
    /// last-capsule digest that disagrees with its reason.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("marker.version", self.version)?;
        require_nonzero_v1("marker.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("marker.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("marker.wallet_id", &self.wallet_id)?;
        self.payment_key.validate()?;
        let enrollment = matches!(self.state, KagemushaWalletMarkerStateV1::Enrollment { .. });
        if enrollment != (self.generation == 0) {
            return Err(invalid_v1("marker.generation"));
        }
        match self.state {
            KagemushaWalletMarkerStateV1::Enrollment {
                challenge_digest,
                enrollment_id,
            } => {
                require_nonzero_v1("marker.challenge_digest", &challenge_digest)?;
                if enrollment_id
                    != kagemusha_wallet_enrollment_id_v1(&challenge_digest, &self.payment_key)
                {
                    return Err(invalid_v1("marker.enrollment_id"));
                }
                if self.wallet_id
                    != kagemusha_wallet_id_v1(
                        &self.scheme_id,
                        &self.asset_digest,
                        &self.payment_key,
                        &enrollment_id,
                    )
                {
                    return Err(invalid_v1("marker.wallet_id"));
                }
            }
            KagemushaWalletMarkerStateV1::Head {
                sequence,
                operation_id,
                head,
                capsule_digest,
                predecessor_capsule_digest,
            } => {
                require_nonzero_v1("marker.operation_id", &operation_id)?;
                require_nonzero_v1("marker.capsule_digest", &capsule_digest)?;
                if !head.is_complete() {
                    return Err(invalid_v1("marker.head"));
                }
                if (sequence == 0) != is_zero_v1(&predecessor_capsule_digest) {
                    return Err(invalid_v1("marker.predecessor_capsule_digest"));
                }
            }
            KagemushaWalletMarkerStateV1::Terminal {
                reason,
                last_capsule_digest,
            } => {
                let abandoned = reason == KagemushaWalletTerminalReasonV1::Abandoned;
                if abandoned != is_zero_v1(&last_capsule_digest) {
                    return Err(invalid_v1("marker.last_capsule_digest"));
                }
            }
        }
        Ok(())
    }

    /// Validate `self` as the direct successor generation of `previous` (§4.2).
    ///
    /// Enrollment is followed by the Bootstrap head or abandonment; a head by the next head
    /// (sequence plus one, linked capsule) or custody deletion; a terminal marker by nothing.
    ///
    /// # Errors
    ///
    /// Rejects invalid markers, another scheme, asset, wallet or key, a generation that is not
    /// the predecessor's plus one, and any other transition.
    pub fn validate_successor_of(&self, previous: &Self) -> WalletResult<()> {
        self.validate()?;
        previous.validate()?;
        require_scheme_v1("marker.scheme_id", &self.scheme_id, &previous.scheme_id)?;
        if self.asset_digest != previous.asset_digest
            || self.wallet_id != previous.wallet_id
            || self.payment_key != previous.payment_key
        {
            return Err(invalid_v1("marker.identity"));
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or_else(|| overflow_v1("marker.generation"))?;
        if self.generation != generation {
            return Err(invalid_v1("marker.generation"));
        }
        let follows = match (previous.state, self.state) {
            (
                KagemushaWalletMarkerStateV1::Enrollment { .. },
                KagemushaWalletMarkerStateV1::Head { sequence, .. },
            ) => sequence == 0,
            (
                KagemushaWalletMarkerStateV1::Enrollment { .. },
                KagemushaWalletMarkerStateV1::Terminal { reason, .. },
            ) => reason == KagemushaWalletTerminalReasonV1::Abandoned,
            (
                KagemushaWalletMarkerStateV1::Head {
                    sequence: previous_sequence,
                    capsule_digest,
                    ..
                },
                KagemushaWalletMarkerStateV1::Head {
                    sequence,
                    predecessor_capsule_digest,
                    ..
                },
            ) => {
                previous_sequence.checked_add(1) == Some(sequence)
                    && predecessor_capsule_digest == capsule_digest
            }
            (
                KagemushaWalletMarkerStateV1::Head { capsule_digest, .. },
                KagemushaWalletMarkerStateV1::Terminal {
                    reason,
                    last_capsule_digest,
                },
            ) => {
                reason == KagemushaWalletTerminalReasonV1::CustodyDeleted
                    && last_capsule_digest == capsule_digest
            }
            _ => false,
        };
        if !follows {
            return Err(invalid_v1("marker.state"));
        }
        Ok(())
    }

    /// Next-generation marker selecting `state`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_successor_of`] rejects.
    pub fn successor(&self, state: KagemushaWalletMarkerStateV1) -> WalletResult<Self> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| overflow_v1("marker.generation"))?;
        let next = Self {
            generation,
            state,
            ..*self
        };
        next.validate_successor_of(self)?;
        Ok(next)
    }

    /// Require that this head marker selects exactly `capsule`'s head.
    ///
    /// # Errors
    ///
    /// Rejects invalid values, another scheme or wallet, and a marker state other than the
    /// capsule's head state.
    pub fn require_capsule(&self, capsule: &KagemushaWalletRecoveryCapsuleV1) -> WalletResult<()> {
        self.validate()?;
        let head = capsule.head_marker_state();
        let capsule = capsule.body();
        require_scheme_v1("marker.scheme_id", &self.scheme_id, &capsule.scheme_id)?;
        if self.wallet_id != capsule.wallet_id {
            return Err(invalid_v1("marker.wallet_id"));
        }
        if self.state != head {
            return Err(invalid_v1("marker.capsule"));
        }
        Ok(())
    }

    /// Bootstrap effect installing the zero state from this generation-0 enrollment marker.
    ///
    /// # Errors
    ///
    /// Rejects an invalid marker or one that is not the enrollment marker.
    pub fn bootstrap_effect(&self) -> WalletResult<KagemushaWalletEffectV1> {
        let KagemushaWalletMarkerStateV1::Enrollment { enrollment_id, .. } = self.state else {
            return Err(invalid_v1("marker.state"));
        };
        Ok(KagemushaWalletEffectV1::Bootstrap {
            enrollment_id,
            enrollment_marker: self.marker_digest()?,
        })
    }

    /// Marker digest `H("marker", canonical frame)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::to_canonical_bytes`] rejects.
    pub fn marker_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::Marker,
            &self.to_canonical_bytes()?,
        ))
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid marker or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1)
    }

    /// Decode one canonical marker frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let marker: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1)?;
        marker.require_versions()?;
        require_scheme_v1("marker.scheme_id", &marker.scheme_id, expected_scheme_id)?;
        marker.validate()?;
        Ok(marker)
    }
}

// ---------------------------------------------------------------------------------------
// Output descriptor (§4.1, design §5.2 and C3)
// ---------------------------------------------------------------------------------------

/// Exact `output` transcript:
/// `u8 kind || statement_digest || proof_digest || payment_digest or zero`.
#[must_use]
pub fn kagemusha_wallet_output_transcript_v1(
    kind: KagemushaWalletOperationKindV1,
    statement_digest: &[u8; 32],
    proof_digest: &[u8; 32],
    payment_digest: &[u8; 32],
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_OUTPUT_TRANSCRIPT_BYTES_V1)
        .u8(kind.tag())
        .digest(statement_digest)
        .digest(proof_digest)
        .digest(payment_digest)
        .finish()
}

/// Receipt-free output digest `H("output", transcript)`.
#[must_use]
pub fn kagemusha_wallet_output_digest_v1(
    kind: KagemushaWalletOperationKindV1,
    statement_digest: &[u8; 32],
    proof_digest: &[u8; 32],
    payment_digest: &[u8; 32],
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::Output,
        &kagemusha_wallet_output_transcript_v1(
            kind,
            statement_digest,
            proof_digest,
            payment_digest,
        ),
    )
}

/// Receipt-free descriptor of one transition's released output (§4.1, design §9.2).
///
/// A Send releases its canonical Payment; every other kind releases its package. The digest
/// covers the statement, the operation-dependent `proof_digest` and, for Receive, the Payment
/// digest the receipt binds; every other kind input (the Send Request, the original Load receipt and finality evidence, the
/// Unload nullifier, the `ArchiveSent` Credited digest, the payer credential) is already bound
/// by the statement. It can therefore be frozen in the capsule before the receipt exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletOutputDescriptorV1"
)]
pub struct KagemushaWalletOutputDescriptorV1 {
    /// Operation kind of the output.
    pub kind: KagemushaWalletOperationKindV1,
    /// Output digest ([`kagemusha_wallet_output_digest_v1`]).
    pub digest: [u8; 32],
}

impl KagemushaWalletOutputDescriptorV1 {
    /// Descriptor of the output of `statement` with `proof_digest` and, for Receive, the
    /// Payment digest.
    ///
    /// # Errors
    ///
    /// Rejects an invalid statement, a zero or noncanonical proof digest, a noncanonical Payment
    /// digest, and a Payment digest present or absent against the operation (present exactly
    /// for Receive).
    pub fn for_transition(
        statement: &KagemushaWalletStatementV1,
        proof_digest: &[u8; 32],
        payment_digest: &[u8; 32],
    ) -> WalletResult<Self> {
        statement.validate()?;
        require_nonzero_field_v1("output.proof_digest", proof_digest)?;
        require_canonical_field_v1("output.payment_digest", payment_digest)?;
        let kind = statement.effect.kind();
        if (kind == KagemushaWalletOperationKindV1::Receive) == is_zero_v1(payment_digest) {
            return Err(invalid_v1("output.payment_digest"));
        }
        Ok(Self {
            kind,
            digest: kagemusha_wallet_output_digest_v1(
                kind,
                &statement.statement_digest()?,
                proof_digest,
                payment_digest,
            ),
        })
    }

    /// Validate the descriptor's fields.
    ///
    /// # Errors
    ///
    /// Rejects a zero digest.
    pub fn validate(&self) -> WalletResult<()> {
        require_nonzero_v1("output.digest", &self.digest)
    }
}

// ---------------------------------------------------------------------------------------
// Recovery capsule (§4.1, design §5.2)
// ---------------------------------------------------------------------------------------

/// Role of one retained input of a recovery capsule.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRetainedInputRoleV1"
)]
pub enum KagemushaWalletRetainedInputRoleV1 {
    /// Canonical Request consumed by Send.
    #[codec(index = 1)]
    Request,
    /// Canonical incoming Payment consumed by Receive.
    #[codec(index = 2)]
    Payment,
    /// Canonical Credited evidence consumed by `ArchiveSent`.
    #[codec(index = 3)]
    Credited,
    /// Canonical ordinary Load receipt consumed by Load.
    #[codec(index = 4)]
    LoadReceipt,
    /// Canonical charge quote consumed by Load or Unload.
    #[codec(index = 5)]
    ChargeQuote,
    /// Exact update custody consumed by `RefreshPolicy`: Blacklist carries the
    /// bounded native complete-original archive reference; other fixed kinds
    /// carry the complete inline signed update. Native restores and authenticates
    /// the full blacklist before using it; the reference is not an issuer verdict.
    #[codec(index = 6)]
    PolicyUpdate,
    /// Canonical certificate set the operation needed.
    #[codec(index = 7)]
    CertificateSet,
    /// Canonical credential the operation consumed.
    #[codec(index = 8)]
    Credential,
    /// Canonical compact ordinary-transaction finality evidence consumed by Load.
    #[codec(index = 9)]
    LoadFinality,
    /// Canonical typed predecessor quota-usage array consumed by a quota refresh.
    #[codec(index = 10)]
    QuotaRefreshWitness,
}

impl KagemushaWalletRetainedInputRoleV1 {
    /// Every role, in tag order.
    pub const ALL: [Self; 10] = [
        Self::Request,
        Self::Payment,
        Self::Credited,
        Self::LoadReceipt,
        Self::ChargeQuote,
        Self::PolicyUpdate,
        Self::CertificateSet,
        Self::Credential,
        Self::LoadFinality,
        Self::QuotaRefreshWitness,
    ];

    /// Tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Payment => 2,
            Self::Credited => 3,
            Self::LoadReceipt => 4,
            Self::ChargeQuote => 5,
            Self::PolicyUpdate => 6,
            Self::CertificateSet => 7,
            Self::Credential => 8,
            Self::LoadFinality => 9,
            Self::QuotaRefreshWitness => 10,
        }
    }
}

/// Exact input bytes retained in a capsule so an interrupted operation resumes offline.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRetainedInputV1"
)]
pub struct KagemushaWalletRetainedInputV1 {
    /// Role of the bytes.
    pub role: KagemushaWalletRetainedInputRoleV1,
    /// Original canonical bytes; never rewritten.
    pub bytes: Vec<u8>,
}

impl KagemushaWalletRetainedInputV1 {
    /// Validate the retained input.
    ///
    /// # Errors
    ///
    /// Rejects empty bytes.
    pub fn validate(&self) -> WalletResult<()> {
        if self.bytes.is_empty() {
            return Err(invalid_v1("capsule.retained_input"));
        }
        Ok(())
    }
}

/// Retained-input roles a capsule of `kind` must carry as fold witnesses (§4.1, design §9.1):
/// every consumed input that Λ verifies for the step and the step itself cannot rebuild.
///
/// Send retains the Request it consumed: the compact Payment binds the receiver's fee schedule
/// only by digest, and `Λ_send` checks the fee terms against it (§§3.2, 6.2). Load retains
/// the original receipt and compact finality evidence so restoration verifies the same
/// ordinary transaction under the independently installed history anchor and source key.
/// Archive retains the historical payer credential and its certificate set because
/// a later credential renewal must not replace the exact Send credential.
// TODO(owner): interim choices kept as is until the owner decides: a Send capsule retains the
// whole Request message, and no Load or Unload capsule retains a ChargeQuote because `Λ_load`
// and `Λ_unload` do not verify ChargeQuote signatures (wire record §7).
const fn required_retained_roles_v1(
    kind: KagemushaWalletOperationKindV1,
) -> &'static [KagemushaWalletRetainedInputRoleV1] {
    use KagemushaWalletRetainedInputRoleV1 as R;
    match kind {
        KagemushaWalletOperationKindV1::Receive => {
            &[R::Request, R::Payment, R::CertificateSet, R::Credential]
        }
        KagemushaWalletOperationKindV1::ArchiveSent => &[
            R::Request,
            R::Payment,
            R::Credited,
            R::Credential,
            R::CertificateSet,
        ],
        KagemushaWalletOperationKindV1::Send => &[R::Request],
        KagemushaWalletOperationKindV1::Load => &[R::LoadReceipt, R::LoadFinality],
        KagemushaWalletOperationKindV1::RefreshPolicy => &[R::PolicyUpdate, R::CertificateSet],
        KagemushaWalletOperationKindV1::Bootstrap
        | KagemushaWalletOperationKindV1::Unload
        | KagemushaWalletOperationKindV1::Retiring => &[],
    }
}

/// Complete private recovery body, validated and frozen before an independent opening is drawn.
///
/// It holds the actual next state, the statement, Ω(pred) for Send, Unload and Retiring, the
/// step proof σ, the Payment digest a Receive receipt binds, the required map nodes, the
/// retained input bytes (the fold witnesses, §4.1) and the receipt-free output descriptor;
/// every byte is bound by the randomized capsule commitment signed in the receipt.
///
/// Each map opening is one depth-32 indexed-tree opening transcript of §3.2 (owner answer A2):
/// a leaf opening or an empty-slot opening, each with exactly 32 siblings.
// TODO(G3): which openings each operation kind retains is fixed with the artifact set; G1
// checks only each opening's layout.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRecoveryBodyV1"
)]
pub struct KagemushaWalletRecoveryBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Operation identity of the transition.
    pub operation_id: [u8; 32],
    /// Operation kind.
    pub kind: KagemushaWalletOperationKindV1,
    /// Digest of the predecessor's capsule; zero for Bootstrap.
    pub predecessor_capsule_digest: [u8; 32],
    /// Actual successor state.
    pub successor_state: KagemushaWalletStateV1,
    /// Transition statement.
    pub statement: KagemushaWalletStatementV1,
    /// Ω(pred) recorded at fold time: present exactly for Send, Unload and Retiring.
    pub predecessor_lineage: KagemushaWalletLineageSlotV1,
    /// Step proof σ.
    pub step_proof: KagemushaWalletStepProofV1,
    /// Full canonical Payment digest of a Receive; zero otherwise.
    pub payment_digest: [u8; 32],
    /// Required map openings: each one §3.2 leaf-opening (1,124 bytes) or empty-slot opening
    /// (1,028 bytes) transcript with exactly 32 siblings.
    pub map_openings: Vec<Vec<u8>>,
    /// Exact input bytes needed to resume and to fold the step.
    pub retained_inputs: Vec<KagemushaWalletRetainedInputV1>,
    /// Receipt-free output descriptor.
    pub output: KagemushaWalletOutputDescriptorV1,
}

impl KagemushaWalletRecoveryBodyV1 {
    /// Decode the one mandatory quota-refresh witness, absent for every other effect.
    /// Its original frame remains covered by the capsule and signed receipt digest.
    /// This checks canonical shape; the transition owner must authenticate its root
    /// against the actual predecessor state before accepting the quota update.
    ///
    /// # Errors
    /// Missing, duplicate, malformed or oversized quota witness, or a witness retained
    /// for an operation other than a quota-share refresh.
    pub fn quota_refresh_witness(
        &self,
    ) -> WalletResult<Option<KagemushaWalletQuotaRefreshWitnessV1>> {
        let required = matches!(
            self.statement.effect,
            KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: KagemushaWalletPolicyUpdateKindV1::QuotaShare,
                ..
            }
        );
        let mut originals = self
            .retained_inputs
            .iter()
            .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness);
        match (required, originals.next(), originals.next()) {
            (false, None, None) => Ok(None),
            (true, Some(original), None) => {
                KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(&original.bytes).map(Some)
            }
            _ => Err(invalid_v1("capsule.quota_refresh_witness")),
        }
    }

    /// Operation-dependent `proof_digest` the receipt and Advance bind (§4.1).
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_proof_digest_v1`] rejects.
    pub fn proof_digest(&self) -> WalletResult<[u8; 32]> {
        kagemusha_wallet_proof_digest_v1(
            self.kind,
            self.predecessor_lineage.lineage(),
            &self.step_proof,
        )
    }

    /// Ω(pred) carried by the capsule, if the operation consumes it.
    #[must_use]
    pub const fn predecessor_lineage(&self) -> Option<&KagemushaWalletLineageV1> {
        self.predecessor_lineage.lineage()
    }

    /// Validate the capsule's self-contained rules.
    ///
    /// The output digest is rebuilt for every kind from the statement, the `proof_digest` and
    /// the Payment digest.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero identities, an invalid state, statement or σ, a successor
    /// state whose commitment is not the statement's successor, a statement or state for
    /// another scheme, wallet, credential, asset, lifecycle, sequence or `next_load`, a kind or
    /// operation identity that does not match the statement, a
    /// predecessor capsule present exactly at Bootstrap, an Ω(pred) present or absent against
    /// the kind or failing the §3.2 consumer equalities or naming another wallet, a successor
    /// `burned_total` other than Ω(pred)'s, a Payment digest present or absent against the
    /// kind, an output descriptor that does not rebuild, a map opening that is not a §3.2
    /// leaf-opening or empty-slot opening transcript with 32 canonical siblings, an empty
    /// retained input, and a missing fold-witness role.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("capsule.version", self.version)?;
        require_nonzero_v1("capsule.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("capsule.wallet_id", &self.wallet_id)?;
        require_nonzero_v1("capsule.operation_id", &self.operation_id)?;
        let state = &self.successor_state;
        let statement = &self.statement;
        state.validate()?;
        statement.validate()?;
        self.step_proof.validate()?;
        self.output.validate()?;
        self.predecessor_lineage.validate_for(self.kind)?;
        require_scheme_v1("capsule.scheme_id", &statement.scheme_id, &self.scheme_id)?;
        require_scheme_v1(
            "capsule.successor_state.scheme_id",
            &state.core.scheme_id,
            &self.scheme_id,
        )?;
        require_canonical_field_v1("capsule.payment_digest", &self.payment_digest)?;
        for (field, matches) in [
            (
                "capsule.successor_state.wallet_id",
                state.core.wallet_id == self.wallet_id,
            ),
            (
                "capsule.successor_state.credential_digest",
                state.core.credential_digest == statement.credential_digest,
            ),
            (
                "capsule.successor_state.asset_digest",
                state.core.asset_digest == statement.asset_digest,
            ),
            (
                "capsule.successor_state.lifecycle",
                state.core.lifecycle == statement.lifecycle,
            ),
            (
                "capsule.successor_state.sequence",
                state.core.sequence == statement.sequence,
            ),
            (
                "capsule.successor_state.next_load",
                state.core.next_load == statement.next_load,
            ),
            ("capsule.kind", self.kind == statement.effect.kind()),
            ("capsule.output.kind", self.output.kind == self.kind),
            (
                "capsule.operation_id",
                self.operation_id == statement.operation_id(&self.wallet_id)?,
            ),
            (
                "capsule.predecessor_capsule_digest",
                (statement.sequence == 0) == is_zero_v1(&self.predecessor_capsule_digest),
            ),
            (
                "capsule.payment_digest",
                (self.kind == KagemushaWalletOperationKindV1::Receive)
                    != is_zero_v1(&self.payment_digest),
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        if let Some(lineage) = self.predecessor_lineage.lineage() {
            statement.validate_against_lineage(&lineage.public)?;
            if lineage.public.wallet_id != self.wallet_id {
                return Err(invalid_v1("capsule.predecessor_lineage.wallet_id"));
            }
            // The successor core carries Ω(pred)'s burned_total, which resynchronizes the core
            // (§3.2).
            if state.core.burned_total != statement.lineage_burned_total {
                return Err(invalid_v1("capsule.successor_state.burned_total"));
            }
        }
        // The capsule holds the actual successor state: its computed commitment is the head the
        // statement and receipt bind (§§3, 4.1).
        if state.commitment()? != statement.successor {
            return Err(invalid_v1("capsule.successor_state.commitment"));
        }
        let rebuilt = KagemushaWalletOutputDescriptorV1::for_transition(
            statement,
            &self.proof_digest()?,
            &self.payment_digest,
        )?;
        if rebuilt != self.output {
            return Err(invalid_v1("capsule.output.digest"));
        }
        for opening in &self.map_openings {
            KagemushaWalletIndexedOpeningV1::from_transcript(opening)
                .map_err(|_| invalid_v1("capsule.map_openings"))?;
        }
        for input in &self.retained_inputs {
            input.validate()?;
        }
        let _ = self.quota_refresh_witness()?;
        for role in required_retained_roles_v1(self.kind) {
            if !self.retained_inputs.iter().any(|input| input.role == *role) {
                return Err(invalid_v1("capsule.retained_inputs"));
            }
        }
        Ok(())
    }

    /// Consume this body and retain its exact canonical frame before opening sampling.
    ///
    /// The fixed-width wrapper capacity is checked with a zero placeholder opening;
    /// no commitment is evaluated and no opening is chosen by this operation.
    ///
    /// # Errors
    /// Rejects every invalid body and a body whose complete wrapper would exceed the cap.
    pub fn freeze(self) -> WalletResult<KagemushaWalletFrozenRecoveryBodyV1> {
        let body_frame = self.to_canonical_bytes()?;
        let _ = encode_frame_v1(
            &KagemushaWalletRecoveryCapsuleFrameV1 {
                body_frame: body_frame.clone(),
                opening: [0; 32],
            },
            KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1,
        )?;
        let body_digest = kagemusha_wallet_digest_v1(Role::CapsuleBody, &body_frame);
        Ok(KagemushaWalletFrozenRecoveryBodyV1 {
            body: self,
            body_frame,
            body_digest,
        })
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid capsule or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1)
    }

    /// Decode one canonical capsule frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let capsule: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1)?;
        capsule.require_versions()?;
        require_scheme_v1("capsule.scheme_id", &capsule.scheme_id, expected_scheme_id)?;
        capsule.validate()?;
        Ok(capsule)
    }
}

/// Immutable canonical recovery body, before its independent opening is sampled.
///
/// This owner exposes no mutable body reference and is consumed when it is sealed.
#[derive(Clone, PartialEq, Eq)]
pub struct KagemushaWalletFrozenRecoveryBodyV1 {
    body: KagemushaWalletRecoveryBodyV1,
    body_frame: Vec<u8>,
    body_digest: [u8; 32],
}

impl core::fmt::Debug for KagemushaWalletFrozenRecoveryBodyV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KagemushaWalletFrozenRecoveryBodyV1")
            .finish_non_exhaustive()
    }
}

impl KagemushaWalletFrozenRecoveryBodyV1 {
    /// The validated immutable recovery body.
    #[must_use]
    pub const fn body(&self) -> &KagemushaWalletRecoveryBodyV1 {
        &self.body
    }

    /// Bind one independently sampled canonical Fp opening to this frozen body.
    ///
    /// Zero is a valid opening. The caller samples only after freezing the body,
    /// and must not reuse an opening for another body. This function never samples,
    /// reduces or replaces an opening, including on a zero-identifier refusal.
    ///
    /// # Errors
    /// Rejects a noncanonical opening, an invalid compiled parameter or a zero
    /// public identifier. The complete wrapper must remain within the private cap.
    pub fn seal(self, opening: [u8; 32]) -> WalletResult<KagemushaWalletRecoveryCapsuleV1> {
        let opening = zeroize::Zeroizing::new(opening);
        let point = capsule_point_v1::<iroha_pasta::Eq>(&self.body_digest, &opening)?;
        let receipt_commitment = super::poseidon::kagemusha_wallet_poseidon_bytes_v1(
            super::poseidon::KAGEMUSHA_WALLET_CAPSULE_COMMITMENT_DOMAIN_V1,
            &point,
        );
        require_nonzero_v1("capsule.commitment", &receipt_commitment)?;
        let wire = KagemushaWalletRecoveryCapsuleFrameV1 {
            body_frame: self.body_frame,
            opening: *opening,
        };
        let frame = encode_frame_v1(&wire, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1)?;
        let custody_digest = kagemusha_wallet_digest_v1(Role::Capsule, &frame);
        Ok(KagemushaWalletRecoveryCapsuleV1 {
            body: Box::new(self.body),
            wire,
            frame,
            custody_digest,
            receipt_commitment,
        })
    }
}

/// The only wire form of a private recovery capsule: exact canonical B, then r.
/// Only the validated owner is exposed to callers; this private DTO carries no cache.
#[derive(Clone, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRecoveryCapsuleV1"
)]
pub(super) struct KagemushaWalletRecoveryCapsuleFrameV1 {
    pub(super) body_frame: Vec<u8>,
    pub(super) opening: [u8; 32],
}

/// Validated immutable private wrapper W and its distinct custody/public identities.
///
/// Only canonical construction or decode can create this owner. Its retained frame
/// authenticates both B and r. No point is duplicated on disk; C is recomputed from
/// the opening and the compiled Eq generator tuple before this owner is created.
/// Cached digests cannot outlive validation or become stale through mutation.
#[derive(Clone, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRecoveryCapsuleV1"
)]
pub struct KagemushaWalletRecoveryCapsuleV1 {
    // Keep the wire owner aligned like its two-field DTO, independent of Body's u128 fields.
    body: Box<KagemushaWalletRecoveryBodyV1>,
    wire: KagemushaWalletRecoveryCapsuleFrameV1,
    frame: Vec<u8>,
    custody_digest: [u8; 32],
    receipt_commitment: [u8; 32],
}

impl Drop for KagemushaWalletRecoveryCapsuleV1 {
    fn drop(&mut self) {
        // Exact durable W is never rewritten; erase only this discarded in-memory copy.
        zeroize::Zeroize::zeroize(&mut self.frame);
    }
}

impl core::fmt::Debug for KagemushaWalletRecoveryCapsuleV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KagemushaWalletRecoveryCapsuleV1")
            .finish_non_exhaustive()
    }
}

impl KagemushaWalletRecoveryCapsuleV1 {
    /// The validated immutable body B; callers cannot replace its proof or fields.
    #[must_use]
    pub fn body(&self) -> &KagemushaWalletRecoveryBodyV1 {
        &self.body
    }

    /// Private selected-custody identity H("capsule", W), never a public receipt value.
    #[must_use]
    pub const fn custody_digest(&self) -> [u8; 32] {
        self.custody_digest
    }

    /// Opaque public identifier `P_bytes(kgwcapc1, canonical(C))` signed by the receipt.
    #[must_use]
    pub const fn receipt_commitment(&self) -> [u8; 32] {
        self.receipt_commitment
    }

    /// Borrow the exact private frame, including its retained opening.
    #[must_use]
    pub fn as_canonical_bytes(&self) -> &[u8] {
        &self.frame
    }

    /// Copy the exact private frame; retries never regenerate its opening or body.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.frame.clone()
    }

    /// The operation-dependent proof digest already validated in B.
    ///
    /// # Errors
    /// Returns the underlying proof-digest validation error.
    pub fn proof_digest(&self) -> WalletResult<[u8; 32]> {
        self.body.proof_digest()
    }

    /// The private marker state selecting this exact wrapper.
    #[must_use]
    pub fn head_marker_state(&self) -> KagemushaWalletMarkerStateV1 {
        KagemushaWalletMarkerStateV1::Head {
            sequence: self.body.statement.sequence,
            operation_id: self.body.operation_id,
            head: self.body.statement.successor,
            capsule_digest: self.custody_digest,
            predecessor_capsule_digest: self.body.predecessor_capsule_digest,
        }
    }

    /// Decode exact W, validate B/r and restore identities from the retained opening.
    ///
    /// # Errors
    /// Rejects oversized or noncanonical wrapper/body frames, the wrong scheme,
    /// invalid body fields, a noncanonical opening or a zero public identifier.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let wire: KagemushaWalletRecoveryCapsuleFrameV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1)?;
        let body =
            KagemushaWalletRecoveryBodyV1::decode_canonical(&wire.body_frame, expected_scheme_id)?;
        let restored = body.freeze()?.seal(wire.opening)?;
        if restored.as_canonical_bytes() != bytes {
            return Err(invalid_v1("capsule.frame"));
        }
        Ok(restored)
    }
}

impl core::fmt::Debug for KagemushaWalletRecoveryCapsuleFrameV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KagemushaWalletRecoveryCapsuleFrameV1")
            .finish_non_exhaustive()
    }
}

impl Drop for KagemushaWalletRecoveryCapsuleFrameV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.opening);
        zeroize::Zeroize::zeroize(&mut self.body_frame);
    }
}

impl iroha_schema::TypeId for KagemushaWalletRecoveryCapsuleV1 {
    fn id() -> String {
        "KagemushaWalletRecoveryCapsuleV1".into()
    }
}

impl IntoSchema for KagemushaWalletRecoveryCapsuleV1 {
    fn type_name() -> String {
        "KagemushaWalletRecoveryCapsuleV1".into()
    }

    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        use iroha_schema::{Declaration, Metadata, NamedFieldsMeta};
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "body_frame".into(),
                        ty: core::any::TypeId::of::<Vec<u8>>(),
                    },
                    Declaration {
                        name: "opening".into(),
                        ty: core::any::TypeId::of::<[u8; 32]>(),
                    },
                ],
            }));
            Vec::<u8>::update_schema_map(map);
            <[u8; 32]>::update_schema_map(map);
        }
    }
}

impl norito::SerializePayload for KagemushaWalletRecoveryCapsuleV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        norito::SerializePayload::serialize(&self.wire, writer)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        norito::SerializePayload::encoded_len_hint(&self.wire)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        norito::SerializePayload::encoded_len_exact(&self.wire)
    }
}

impl<'de> norito::DeserializePayload<'de> for KagemushaWalletRecoveryCapsuleV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("validated canonical KAGEMUSHA recovery capsule")
    }

    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (value, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(norito::Error::LengthMismatch);
        }
        Ok(value)
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for KagemushaWalletRecoveryCapsuleV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
        let (wire, used) =
            norito::core::decode_field_prefix::<KagemushaWalletRecoveryCapsuleFrameV1>(bytes)?;
        // This path also handles capsules nested in an enclosing Norito object.
        // Decode B canonically, retain exactly the supplied r, and rebuild every cache;
        // no unchecked cache-bearing representation can be deserialized.
        let restored = (|| -> WalletResult<Self> {
            let body: KagemushaWalletRecoveryBodyV1 =
                decode_frame_v1(&wire.body_frame, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1)?;
            body.require_versions()?;
            body.freeze()?.seal(wire.opening)
        })()
        .map_err(|error| norito::Error::Message(error.to_string()))?;
        Ok((restored, used))
    }
}

/// The exact existing Eq IPA g[0], g[1], w tuple; no caller can replace it.
const CAPSULE_BASES_V1: [[u8; 32]; 3] = [
    [
        0x45, 0x06, 0x5e, 0xd0, 0x79, 0xbf, 0x38, 0x97, 0x58, 0xf5, 0x91, 0x13, 0x10, 0x95, 0xef,
        0x41, 0x93, 0x10, 0xe8, 0xc7, 0x08, 0xa8, 0x05, 0x85, 0x2b, 0x9b, 0x77, 0xbe, 0xd8, 0xc7,
        0xec, 0xbd,
    ],
    [
        0xe0, 0xc0, 0x80, 0x26, 0x86, 0xd3, 0xed, 0x57, 0x1f, 0x7f, 0x33, 0x99, 0x52, 0x6b, 0x24,
        0x46, 0x0b, 0x16, 0xac, 0xe4, 0x61, 0xeb, 0xda, 0x9d, 0xcf, 0xe6, 0xe5, 0xb7, 0xb2, 0x98,
        0xc1, 0x8c,
    ],
    [
        0x75, 0x20, 0xd9, 0x6f, 0x3e, 0x5c, 0xd4, 0x17, 0x60, 0x36, 0x71, 0x51, 0x60, 0x8b, 0x54,
        0x82, 0x18, 0x83, 0xc1, 0x0c, 0x4b, 0x9a, 0x4f, 0xf2, 0xbe, 0xae, 0x22, 0x7b, 0xef, 0x94,
        0xbc, 0xab,
    ],
];

fn capsule_point_v1<C: iroha_pasta::PastaCurve<ScalarExt = iroha_pasta::Fp>>(
    body_digest: &[u8; 32],
    opening: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    use iroha_pasta::{Fp, PastaField};
    let scalar = |bytes: &[u8; 32]| {
        let mut limbs = zeroize::Zeroizing::new([0_u64; 4]);
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut word = zeroize::Zeroizing::new([0; 8]);
            word.copy_from_slice(chunk);
            *limb = u64::from_le_bytes(*word);
        }
        Option::<Fp>::from(Fp::from_canonical_limbs(*limbs))
            .ok_or_else(|| invalid_v1("capsule.opening"))
    };
    let mut low = [0; 32];
    let mut high = [0; 32];
    low[..16].copy_from_slice(&body_digest[..16]);
    high[..16].copy_from_slice(&body_digest[16..]);
    let scalars = zeroize::Zeroizing::new([scalar(&low)?, scalar(&high)?, scalar(opening)?]);
    let point = |bytes| {
        Option::<C>::from(C::from_bytes(bytes))
            .ok_or_else(|| invalid_v1("capsule.commitment_parameters"))
    };
    // `*` is the existing fixed-length constant-time secret-scalar kernel, unlike
    // public variable-time MSM. Decompression sees only the compiled public bases.
    let commitment = point(&CAPSULE_BASES_V1[0])? * scalars[0]
        + point(&CAPSULE_BASES_V1[1])? * scalars[1]
        + point(&CAPSULE_BASES_V1[2])? * scalars[2];
    // Identity C has its one canonical zero encoding and is accepted here.
    Ok(commitment.to_bytes())
}

// ---------------------------------------------------------------------------------------
// Completion record (§4.1, design §5.2)
// ---------------------------------------------------------------------------------------

/// Durable completion record: the receipt and the exact released output bytes, excluded from
/// the capsule digest (§4.1).
///
/// Retries return these exact bytes; a released result is never regenerated.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCompletionRecordV1"
)]
pub struct KagemushaWalletCompletionRecordV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Operation identity.
    pub operation_id: [u8; 32],
    /// Private H("capsule", W) selecting the exact wrapper; not the signed public commitment.
    pub capsule_digest: [u8; 32],
    /// Commit receipt.
    pub receipt: KagemushaWalletReceiptV1,
    /// Exact canonical output: the Payment for Send, the package otherwise.
    pub output: Vec<u8>,
}

impl KagemushaWalletCompletionRecordV1 {
    /// Completion record of `capsule` with its `receipt` and released `output` bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid capsule and what [`Self::validate`] rejects.
    pub fn new(
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        receipt: KagemushaWalletReceiptV1,
        output: Vec<u8>,
    ) -> WalletResult<Self> {
        let record = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            wallet_id: capsule.body().wallet_id,
            operation_id: capsule.body().operation_id,
            capsule_digest: capsule.custody_digest(),
            receipt,
            output,
        };
        record.require_capsule(capsule)?;
        Ok(record)
    }

    /// Validate the record's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero identities, an invalid receipt or one for another
    /// operation, and empty or oversized output bytes. This format check cannot
    /// authenticate the private/public capsule join; use [`Self::require_capsule`]
    /// or [`Self::verify`] with the selected immutable owner for that authority.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("completion.version", self.version)?;
        require_nonzero_v1("completion.wallet_id", &self.wallet_id)?;
        require_nonzero_v1("completion.operation_id", &self.operation_id)?;
        require_nonzero_v1("completion.capsule_digest", &self.capsule_digest)?;
        self.receipt.validate()?;
        if self.receipt.operation_id != self.operation_id {
            return Err(invalid_v1("completion.receipt.operation_id"));
        }
        if self.output.is_empty() || self.output.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(invalid_v1("completion.output"));
        }
        Ok(())
    }

    /// Authenticate both private custody and the distinct signed public commitment.
    ///
    /// # Errors
    /// Rejects invalid record fields, another private wrapper, wallet or operation,
    /// or a receipt whose commitment does not derive from that exact wrapper.
    pub fn require_capsule(&self, capsule: &KagemushaWalletRecoveryCapsuleV1) -> WalletResult<()> {
        self.validate()?;
        if capsule.custody_digest() != self.capsule_digest {
            return Err(invalid_v1("completion.capsule_digest"));
        }
        if capsule.body().wallet_id != self.wallet_id {
            return Err(invalid_v1("completion.wallet_id"));
        }
        if capsule.body().operation_id != self.operation_id {
            return Err(invalid_v1("completion.operation_id"));
        }
        if capsule.receipt_commitment() != self.receipt.capsule_commitment {
            return Err(invalid_v1("completion.receipt.capsule_commitment"));
        }
        Ok(())
    }

    /// Verify the record against its capsule under `credential` (design §9.3).
    ///
    /// The record is valid iff the receipt verifies over the capsule commitment, the output decodes
    /// as the capsule's kind, its embedded receipt equals the record's, its statement, Ω(pred)
    /// and σ are the capsule's, its receipt binds the capsule's Payment digest, and its
    /// receipt-free parts rebuild the capsule's output descriptor. A Send output is the
    /// compact Payment, whose predecessor payment key and credential digest must be this
    /// credential's. Returns the released package's digests.
    ///
    /// # Errors
    ///
    /// Rejects an invalid record or capsule, another capsule, wallet or operation, output bytes
    /// that do not decode as the declared kind or as a valid Payment by this credential, an
    /// embedded receipt, statement, Ω(pred) or σ other than the record's and capsule's, an
    /// output descriptor that does not rebuild, and a receipt that does not verify.
    pub fn verify(
        &self,
        credential: &KagemushaWalletCredentialV1,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
    ) -> WalletResult<KagemushaWalletPackageDigestsV1> {
        self.require_capsule(capsule)?;
        let capsule = capsule.body();
        if credential.body.wallet_id != self.wallet_id {
            return Err(invalid_v1("completion.wallet_id"));
        }
        let package = if capsule.kind == KagemushaWalletOperationKindV1::Send {
            let payment =
                KagemushaWalletPaymentV1::decode_canonical(&self.output, &capsule.scheme_id)?;
            let omega = &payment
                .send
                .lineage
                .lineage()
                .ok_or_else(|| invalid_v1("lineage.slot"))?
                .public;
            if omega.payment_key != credential.body.payment_key
                || omega.credential_digest != credential.credential_digest()
            {
                return Err(invalid_v1("completion.credential"));
            }
            payment.send
        } else {
            let package: KagemushaWalletPackageV1 =
                decode_frame_v1(&self.output, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
            package.require_versions()?;
            package.validate()?;
            package
        };
        if package.receipt != self.receipt {
            return Err(invalid_v1("completion.receipt"));
        }
        let capsule_lineage = &capsule.predecessor_lineage;
        if package.statement != capsule.statement
            || package.step_proof != capsule.step_proof
            || package.lineage != *capsule_lineage
        {
            return Err(invalid_v1("completion.output"));
        }
        if package.receipt.payment_digest != capsule.payment_digest {
            return Err(invalid_v1("completion.receipt.payment_digest"));
        }
        let rebuilt = KagemushaWalletOutputDescriptorV1::for_transition(
            &package.statement,
            &package.proof_digest()?,
            &package.receipt.payment_digest,
        )?;
        if rebuilt != capsule.output {
            return Err(invalid_v1("completion.output.digest"));
        }
        package.verify(credential)
    }

    /// Completion digest `H("completion", canonical frame)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::to_canonical_bytes`] rejects.
    pub fn completion_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::Completion,
            &self.to_canonical_bytes()?,
        ))
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid record or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1)
    }

    /// Decode one canonical completion record of `expected_wallet_id`.
    ///
    /// The record carries no scheme field; its wallet identity is the expected binding.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// wallet, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_wallet_id: &[u8; 32]) -> WalletResult<Self> {
        let record: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1)?;
        record.require_versions()?;
        if record.wallet_id != *expected_wallet_id {
            return Err(invalid_v1("completion.wallet_id"));
        }
        record.validate()?;
        Ok(record)
    }
}

// ---------------------------------------------------------------------------------------
// Fold record (§§3.1, 4.1, design §9.5)
// ---------------------------------------------------------------------------------------

/// Durable record of one self-verified lineage proof Ω of a folded head (§3.1 step 5).
///
/// One Λ covers the contiguous run `first_sequence..=sequence`; only the last head of the run
/// receives Ω and becomes folded. Each head has at most one recorded Ω, and every Lineage
/// message, Payment and ledger package from that head carries exactly `lineage`. Its digest is
/// `H("fold", canonical frame)`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFoldRecordV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletFoldRecordV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Wallet incarnation.
    pub wallet_id: [u8; 32],
    /// First step sequence covered by this Λ run.
    pub first_sequence: u128,
    /// Sequence of the folded head.
    pub sequence: u128,
    /// Folded head commitment.
    pub head: KagemushaWalletStateCommitmentV1,
    /// Capsule digest of the folded head.
    pub capsule_digest: [u8; 32],
    /// Exact Ω bytes recorded for the head.
    pub lineage: KagemushaWalletLineageV1,
}

impl KagemushaWalletFoldRecordV1 {
    /// Validate the record's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero identities, an incomplete head, an invalid Ω or one for
    /// another head, scheme or wallet, and a run that starts after its head.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("fold.version", self.version)?;
        require_nonzero_v1("fold.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("fold.wallet_id", &self.wallet_id)?;
        require_nonzero_v1("fold.capsule_digest", &self.capsule_digest)?;
        if !self.head.is_complete() {
            return Err(invalid_v1("fold.head"));
        }
        self.lineage.validate()?;
        let omega = &self.lineage.public;
        require_scheme_v1("fold.lineage.scheme_id", &omega.scheme_id, &self.scheme_id)?;
        if omega.wallet_id != self.wallet_id {
            return Err(invalid_v1("fold.lineage.wallet_id"));
        }
        if omega.head != self.head {
            return Err(invalid_v1("fold.lineage.head"));
        }
        if self.first_sequence > self.sequence {
            return Err(invalid_v1("fold.first_sequence"));
        }
        Ok(())
    }

    /// Lineage digest of the recorded Ω.
    #[must_use]
    pub fn lineage_digest(&self) -> [u8; 32] {
        self.lineage.lineage_digest()
    }

    /// Fold digest `H("fold", canonical frame)`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::to_canonical_bytes`] rejects.
    pub fn fold_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::Fold,
            &self.to_canonical_bytes()?,
        ))
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid record or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1)
    }

    /// Decode one canonical fold record frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let record: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1)?;
        record.require_versions()?;
        require_scheme_v1("fold.scheme_id", &record.scheme_id, expected_scheme_id)?;
        record.validate()?;
        Ok(record)
    }
}

// ---------------------------------------------------------------------------------------
// Version fields (design §0 decode order)
// ---------------------------------------------------------------------------------------

impl WalletVersionsV1 for KagemushaWalletMarkerV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("marker.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletRecoveryBodyV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("capsule.version", self.version)?;
        self.successor_state.require_versions()?;
        self.statement.require_versions()?;
        self.predecessor_lineage.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletCompletionRecordV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("completion.version", self.version)?;
        self.receipt.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletFoldRecordV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("fold.version", self.version)?;
        self.lineage.require_versions()
    }
}
